rule TTP_XOR_WriteProcessMemory_b333 {
  strings:
    $key_b333 = { e4 41 [2] d6 63 [2] d0 56 [2] fe 56 [2] c1 4a }

  condition:
    any of them
}