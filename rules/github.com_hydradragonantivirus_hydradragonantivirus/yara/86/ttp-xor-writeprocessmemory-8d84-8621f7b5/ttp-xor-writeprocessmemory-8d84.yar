rule TTP_XOR_WriteProcessMemory_8d84 {
  strings:
    $key_8d84 = { da f6 [2] e8 d4 [2] ee e1 [2] c0 e1 [2] ff fd }

  condition:
    any of them
}