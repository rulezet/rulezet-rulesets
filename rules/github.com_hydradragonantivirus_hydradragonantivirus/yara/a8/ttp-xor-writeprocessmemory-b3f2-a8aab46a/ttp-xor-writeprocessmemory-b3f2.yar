rule TTP_XOR_WriteProcessMemory_b3f2 {
  strings:
    $key_b3f2 = { e4 80 [2] d6 a2 [2] d0 97 [2] fe 97 [2] c1 8b }

  condition:
    any of them
}