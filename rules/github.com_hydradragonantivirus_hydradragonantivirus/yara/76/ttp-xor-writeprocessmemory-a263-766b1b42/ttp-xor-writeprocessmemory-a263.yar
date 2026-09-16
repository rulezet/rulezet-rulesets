rule TTP_XOR_WriteProcessMemory_a263 {
  strings:
    $key_a263 = { f5 11 [2] c7 33 [2] c1 06 [2] ef 06 [2] d0 1a }

  condition:
    any of them
}