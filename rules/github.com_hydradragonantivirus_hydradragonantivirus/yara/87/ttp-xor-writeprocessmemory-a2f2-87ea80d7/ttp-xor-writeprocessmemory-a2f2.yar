rule TTP_XOR_WriteProcessMemory_a2f2 {
  strings:
    $key_a2f2 = { f5 80 [2] c7 a2 [2] c1 97 [2] ef 97 [2] d0 8b }

  condition:
    any of them
}