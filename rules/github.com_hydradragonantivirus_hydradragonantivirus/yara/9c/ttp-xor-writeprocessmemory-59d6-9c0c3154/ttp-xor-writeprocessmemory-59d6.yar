rule TTP_XOR_WriteProcessMemory_59d6 {
  strings:
    $key_59d6 = { 0e a4 [2] 3c 86 [2] 3a b3 [2] 14 b3 [2] 2b af }

  condition:
    any of them
}