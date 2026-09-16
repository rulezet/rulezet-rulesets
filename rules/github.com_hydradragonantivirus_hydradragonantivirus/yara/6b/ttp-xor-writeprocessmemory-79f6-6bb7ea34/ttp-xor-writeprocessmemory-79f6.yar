rule TTP_XOR_WriteProcessMemory_79f6 {
  strings:
    $key_79f6 = { 2e 84 [2] 1c a6 [2] 1a 93 [2] 34 93 [2] 0b 8f }

  condition:
    any of them
}