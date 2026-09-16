rule TTP_XOR_WriteProcessMemory_a202 {
  strings:
    $key_a202 = { f5 70 [2] c7 52 [2] c1 67 [2] ef 67 [2] d0 7b }

  condition:
    any of them
}