rule TTP_XOR_WriteProcessMemory_64f6 {
  strings:
    $key_64f6 = { 33 84 [2] 01 a6 [2] 07 93 [2] 29 93 [2] 16 8f }

  condition:
    any of them
}