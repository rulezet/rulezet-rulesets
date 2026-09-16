rule TTP_XOR_WriteProcessMemory_a6a4 {
  strings:
    $key_a6a4 = { f1 d6 [2] c3 f4 [2] c5 c1 [2] eb c1 [2] d4 dd }

  condition:
    any of them
}