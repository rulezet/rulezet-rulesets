rule TTP_XOR_WriteProcessMemory_a4c3 {
  strings:
    $key_a4c3 = { f3 b1 [2] c1 93 [2] c7 a6 [2] e9 a6 [2] d6 ba }

  condition:
    any of them
}