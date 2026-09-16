rule TTP_XOR_WriteProcessMemory_40a6 {
  strings:
    $key_40a6 = { 17 d4 [2] 25 f6 [2] 23 c3 [2] 0d c3 [2] 32 df }

  condition:
    any of them
}