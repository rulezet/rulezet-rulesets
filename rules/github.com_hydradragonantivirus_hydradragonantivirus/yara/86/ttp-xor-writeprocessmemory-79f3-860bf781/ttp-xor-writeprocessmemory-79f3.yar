rule TTP_XOR_WriteProcessMemory_79f3 {
  strings:
    $key_79f3 = { 2e 81 [2] 1c a3 [2] 1a 96 [2] 34 96 [2] 0b 8a }

  condition:
    any of them
}