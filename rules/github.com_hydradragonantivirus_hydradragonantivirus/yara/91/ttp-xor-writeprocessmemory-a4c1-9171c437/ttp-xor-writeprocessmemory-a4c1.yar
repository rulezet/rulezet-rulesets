rule TTP_XOR_WriteProcessMemory_a4c1 {
  strings:
    $key_a4c1 = { f3 b3 [2] c1 91 [2] c7 a4 [2] e9 a4 [2] d6 b8 }

  condition:
    any of them
}