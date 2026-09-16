rule TTP_XOR_WriteProcessMemory_a5c3 {
  strings:
    $key_a5c3 = { f2 b1 [2] c0 93 [2] c6 a6 [2] e8 a6 [2] d7 ba }

  condition:
    any of them
}