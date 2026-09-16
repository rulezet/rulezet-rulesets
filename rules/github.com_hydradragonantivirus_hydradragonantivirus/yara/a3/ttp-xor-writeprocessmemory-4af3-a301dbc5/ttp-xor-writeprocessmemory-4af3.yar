rule TTP_XOR_WriteProcessMemory_4af3 {
  strings:
    $key_4af3 = { 1d 81 [2] 2f a3 [2] 29 96 [2] 07 96 [2] 38 8a }

  condition:
    any of them
}