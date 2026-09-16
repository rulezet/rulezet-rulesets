rule TTP_XOR_WriteProcessMemory_b343 {
  strings:
    $key_b343 = { e4 31 [2] d6 13 [2] d0 26 [2] fe 26 [2] c1 3a }

  condition:
    any of them
}