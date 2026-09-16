rule TTP_XOR_WriteProcessMemory_8cd8 {
  strings:
    $key_8cd8 = { db aa [2] e9 88 [2] ef bd [2] c1 bd [2] fe a1 }

  condition:
    any of them
}