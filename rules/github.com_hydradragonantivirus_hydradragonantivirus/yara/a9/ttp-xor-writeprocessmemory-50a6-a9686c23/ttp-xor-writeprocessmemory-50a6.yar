rule TTP_XOR_WriteProcessMemory_50a6 {
  strings:
    $key_50a6 = { 07 d4 [2] 35 f6 [2] 33 c3 [2] 1d c3 [2] 22 df }

  condition:
    any of them
}