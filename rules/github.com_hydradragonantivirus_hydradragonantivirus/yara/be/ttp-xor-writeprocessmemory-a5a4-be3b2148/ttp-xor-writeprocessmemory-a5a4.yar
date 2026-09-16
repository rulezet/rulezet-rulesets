rule TTP_XOR_WriteProcessMemory_a5a4 {
  strings:
    $key_a5a4 = { f2 d6 [2] c0 f4 [2] c6 c1 [2] e8 c1 [2] d7 dd }

  condition:
    any of them
}