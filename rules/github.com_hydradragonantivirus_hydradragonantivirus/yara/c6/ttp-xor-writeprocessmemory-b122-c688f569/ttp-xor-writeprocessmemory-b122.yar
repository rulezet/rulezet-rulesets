rule TTP_XOR_WriteProcessMemory_b122 {
  strings:
    $key_b122 = { e6 50 [2] d4 72 [2] d2 47 [2] fc 47 [2] c3 5b }

  condition:
    any of them
}