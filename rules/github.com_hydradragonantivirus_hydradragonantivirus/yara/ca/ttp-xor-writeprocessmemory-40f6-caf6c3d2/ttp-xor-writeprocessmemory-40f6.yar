rule TTP_XOR_WriteProcessMemory_40f6 {
  strings:
    $key_40f6 = { 17 84 [2] 25 a6 [2] 23 93 [2] 0d 93 [2] 32 8f }

  condition:
    any of them
}