rule TTP_XOR_WriteProcessMemory_25b4 {
  strings:
    $key_25b4 = { 72 c6 [2] 40 e4 [2] 46 d1 [2] 68 d1 [2] 57 cd }

  condition:
    any of them
}