rule TTP_XOR_WriteProcessMemory_8da4 {
  strings:
    $key_8da4 = { da d6 [2] e8 f4 [2] ee c1 [2] c0 c1 [2] ff dd }

  condition:
    any of them
}