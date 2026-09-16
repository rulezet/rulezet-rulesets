rule TTP_XOR_WriteProcessMemory_a3b1 {
  strings:
    $key_a3b1 = { f4 c3 [2] c6 e1 [2] c0 d4 [2] ee d4 [2] d1 c8 }

  condition:
    any of them
}