rule TTP_XOR_WriteProcessMemory_b3f3 {
  strings:
    $key_b3f3 = { e4 81 [2] d6 a3 [2] d0 96 [2] fe 96 [2] c1 8a }

  condition:
    any of them
}