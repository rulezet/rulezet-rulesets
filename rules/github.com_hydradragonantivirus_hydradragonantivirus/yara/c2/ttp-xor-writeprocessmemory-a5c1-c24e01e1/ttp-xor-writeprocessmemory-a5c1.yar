rule TTP_XOR_WriteProcessMemory_a5c1 {
  strings:
    $key_a5c1 = { f2 b3 [2] c0 91 [2] c6 a4 [2] e8 a4 [2] d7 b8 }

  condition:
    any of them
}