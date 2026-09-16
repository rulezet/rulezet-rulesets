rule TTP_XOR_WriteProcessMemory_3bd6 {
  strings:
    $key_3bd6 = { 6c a4 [2] 5e 86 [2] 58 b3 [2] 76 b3 [2] 49 af }

  condition:
    any of them
}