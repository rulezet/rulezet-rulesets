rule TTP_XOR_WriteProcessMemory_50f6 {
  strings:
    $key_50f6 = { 07 84 [2] 35 a6 [2] 33 93 [2] 1d 93 [2] 22 8f }

  condition:
    any of them
}