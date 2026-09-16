rule TTP_XOR_WriteProcessMemory_a266 {
  strings:
    $key_a266 = { f5 14 [2] c7 36 [2] c1 03 [2] ef 03 [2] d0 1f }

  condition:
    any of them
}