rule TTP_XOR_WriteProcessMemory_a2c3 {
  strings:
    $key_a2c3 = { f5 b1 [2] c7 93 [2] c1 a6 [2] ef a6 [2] d0 ba }

  condition:
    any of them
}