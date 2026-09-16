rule TTP_XOR_WriteProcessMemory_6503 {
  strings:
    $key_6503 = { 32 71 [2] 00 53 [2] 06 66 [2] 28 66 [2] 17 7a }

  condition:
    any of them
}