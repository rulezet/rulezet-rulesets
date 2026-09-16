rule TTP_XOR_WriteProcessMemory_a380 {
  strings:
    $key_a380 = { f4 f2 [2] c6 d0 [2] c0 e5 [2] ee e5 [2] d1 f9 }

  condition:
    any of them
}