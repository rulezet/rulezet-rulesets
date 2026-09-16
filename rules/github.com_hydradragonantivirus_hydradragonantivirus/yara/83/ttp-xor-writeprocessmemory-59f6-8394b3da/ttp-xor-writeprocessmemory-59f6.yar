rule TTP_XOR_WriteProcessMemory_59f6 {
  strings:
    $key_59f6 = { 0e 84 [2] 3c a6 [2] 3a 93 [2] 14 93 [2] 2b 8f }

  condition:
    any of them
}