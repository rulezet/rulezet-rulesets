rule TTP_XOR_WriteProcessMemory_b3a4 {
  strings:
    $key_b3a4 = { e4 d6 [2] d6 f4 [2] d0 c1 [2] fe c1 [2] c1 dd }

  condition:
    any of them
}