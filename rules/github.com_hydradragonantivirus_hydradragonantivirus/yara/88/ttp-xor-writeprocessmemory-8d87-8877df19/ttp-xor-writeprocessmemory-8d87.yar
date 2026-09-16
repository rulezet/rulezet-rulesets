rule TTP_XOR_WriteProcessMemory_8d87 {
  strings:
    $key_8d87 = { da f5 [2] e8 d7 [2] ee e2 [2] c0 e2 [2] ff fe }

  condition:
    any of them
}