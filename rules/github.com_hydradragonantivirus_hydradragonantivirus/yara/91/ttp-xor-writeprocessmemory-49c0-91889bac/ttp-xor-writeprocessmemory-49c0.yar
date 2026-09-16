rule TTP_XOR_WriteProcessMemory_49c0 {
  strings:
    $key_49c0 = { 1e b2 [2] 2c 90 [2] 2a a5 [2] 04 a5 [2] 3b b9 }

  condition:
    any of them
}