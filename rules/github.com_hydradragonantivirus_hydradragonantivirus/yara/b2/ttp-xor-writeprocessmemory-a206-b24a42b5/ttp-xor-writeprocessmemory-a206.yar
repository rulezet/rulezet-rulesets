rule TTP_XOR_WriteProcessMemory_a206 {
  strings:
    $key_a206 = { f5 74 [2] c7 56 [2] c1 63 [2] ef 63 [2] d0 7f }

  condition:
    any of them
}