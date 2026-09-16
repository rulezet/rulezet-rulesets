rule TTP_XOR_WriteProcessMemory_a296 {
  strings:
    $key_a296 = { f5 e4 [2] c7 c6 [2] c1 f3 [2] ef f3 [2] d0 ef }

  condition:
    any of them
}