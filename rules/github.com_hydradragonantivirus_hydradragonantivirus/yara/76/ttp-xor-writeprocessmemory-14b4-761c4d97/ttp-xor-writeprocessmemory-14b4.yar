rule TTP_XOR_WriteProcessMemory_14b4 {
  strings:
    $key_14b4 = { 43 c6 [2] 71 e4 [2] 77 d1 [2] 59 d1 [2] 66 cd }

  condition:
    any of them
}