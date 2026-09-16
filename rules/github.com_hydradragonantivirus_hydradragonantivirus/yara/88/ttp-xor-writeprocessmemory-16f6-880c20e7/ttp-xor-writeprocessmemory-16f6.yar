rule TTP_XOR_WriteProcessMemory_16f6 {
  strings:
    $key_16f6 = { 41 84 [2] 73 a6 [2] 75 93 [2] 5b 93 [2] 64 8f }

  condition:
    any of them
}