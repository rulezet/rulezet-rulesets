rule TTP_XOR_WriteProcessMemory_77f6 {
  strings:
    $key_77f6 = { 20 84 [2] 12 a6 [2] 14 93 [2] 3a 93 [2] 05 8f }

  condition:
    any of them
}