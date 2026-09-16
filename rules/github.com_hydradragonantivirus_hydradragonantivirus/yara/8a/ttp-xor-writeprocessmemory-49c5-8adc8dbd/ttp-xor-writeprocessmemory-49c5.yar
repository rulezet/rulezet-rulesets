rule TTP_XOR_WriteProcessMemory_49c5 {
  strings:
    $key_49c5 = { 1e b7 [2] 2c 95 [2] 2a a0 [2] 04 a0 [2] 3b bc }

  condition:
    any of them
}