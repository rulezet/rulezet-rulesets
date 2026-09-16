rule TTP_XOR_WriteProcessMemory_59d4 {
  strings:
    $key_59d4 = { 0e a6 [2] 3c 84 [2] 3a b1 [2] 14 b1 [2] 2b ad }

  condition:
    any of them
}