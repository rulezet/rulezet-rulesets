rule TTP_XOR_WriteProcessMemory_49f6 {
  strings:
    $key_49f6 = { 1e 84 [2] 2c a6 [2] 2a 93 [2] 04 93 [2] 3b 8f }

  condition:
    any of them
}