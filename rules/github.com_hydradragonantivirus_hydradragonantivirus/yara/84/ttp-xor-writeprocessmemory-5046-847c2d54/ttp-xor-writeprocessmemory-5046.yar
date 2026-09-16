rule TTP_XOR_WriteProcessMemory_5046 {
  strings:
    $key_5046 = { 07 34 [2] 35 16 [2] 33 23 [2] 1d 23 [2] 22 3f }

  condition:
    any of them
}