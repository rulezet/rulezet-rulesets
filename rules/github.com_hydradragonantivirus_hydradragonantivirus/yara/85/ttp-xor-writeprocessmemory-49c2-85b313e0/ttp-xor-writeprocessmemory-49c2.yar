rule TTP_XOR_WriteProcessMemory_49c2 {
  strings:
    $key_49c2 = { 1e b0 [2] 2c 92 [2] 2a a7 [2] 04 a7 [2] 3b bb }

  condition:
    any of them
}