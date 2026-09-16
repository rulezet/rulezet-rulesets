rule TTP_XOR_WriteProcessMemory_a386 {
  strings:
    $key_a386 = { f4 f4 [2] c6 d6 [2] c0 e3 [2] ee e3 [2] d1 ff }

  condition:
    any of them
}