rule TTP_XOR_WriteProcessMemory_a382 {
  strings:
    $key_a382 = { f4 f0 [2] c6 d2 [2] c0 e7 [2] ee e7 [2] d1 fb }

  condition:
    any of them
}