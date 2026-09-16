rule TTP_XOR_WriteProcessMemory_a385 {
  strings:
    $key_a385 = { f4 f7 [2] c6 d5 [2] c0 e0 [2] ee e0 [2] d1 fc }

  condition:
    any of them
}