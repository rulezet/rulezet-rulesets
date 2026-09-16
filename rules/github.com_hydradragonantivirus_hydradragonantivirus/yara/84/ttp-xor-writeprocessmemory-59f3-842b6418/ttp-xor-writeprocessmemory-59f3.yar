rule TTP_XOR_WriteProcessMemory_59f3 {
  strings:
    $key_59f3 = { 0e 81 [2] 3c a3 [2] 3a 96 [2] 14 96 [2] 2b 8a }

  condition:
    any of them
}