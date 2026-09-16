rule TTP_XOR_WriteProcessMemory_46f6 {
  strings:
    $key_46f6 = { 11 84 [2] 23 a6 [2] 25 93 [2] 0b 93 [2] 34 8f }

  condition:
    any of them
}