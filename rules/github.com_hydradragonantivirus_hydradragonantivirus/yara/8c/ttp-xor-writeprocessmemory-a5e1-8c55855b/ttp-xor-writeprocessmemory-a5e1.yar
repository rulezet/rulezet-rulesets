rule TTP_XOR_WriteProcessMemory_a5e1 {
  strings:
    $key_a5e1 = { f2 93 [2] c0 b1 [2] c6 84 [2] e8 84 [2] d7 98 }

  condition:
    any of them
}