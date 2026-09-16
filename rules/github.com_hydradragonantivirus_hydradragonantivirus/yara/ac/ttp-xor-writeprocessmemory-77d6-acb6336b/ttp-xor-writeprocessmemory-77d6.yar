rule TTP_XOR_WriteProcessMemory_77d6 {
  strings:
    $key_77d6 = { 20 a4 [2] 12 86 [2] 14 b3 [2] 3a b3 [2] 05 af }

  condition:
    any of them
}