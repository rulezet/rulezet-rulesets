rule TTP_XOR_WriteProcessMemory_37d6 {
  strings:
    $key_37d6 = { 60 a4 [2] 52 86 [2] 54 b3 [2] 7a b3 [2] 45 af }

  condition:
    any of them
}