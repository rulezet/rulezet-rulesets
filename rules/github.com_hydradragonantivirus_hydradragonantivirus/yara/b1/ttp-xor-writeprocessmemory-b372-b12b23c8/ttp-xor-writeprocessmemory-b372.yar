rule TTP_XOR_WriteProcessMemory_b372 {
  strings:
    $key_b372 = { e4 00 [2] d6 22 [2] d0 17 [2] fe 17 [2] c1 0b }

  condition:
    any of them
}