rule TTP_XOR_WriteProcessMemory_12b4 {
  strings:
    $key_12b4 = { 45 c6 [2] 77 e4 [2] 71 d1 [2] 5f d1 [2] 60 cd }

  condition:
    any of them
}