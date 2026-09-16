rule TTP_XOR_WriteProcessMemory_57b4 {
  strings:
    $key_57b4 = { 00 c6 [2] 32 e4 [2] 34 d1 [2] 1a d1 [2] 25 cd }

  condition:
    any of them
}