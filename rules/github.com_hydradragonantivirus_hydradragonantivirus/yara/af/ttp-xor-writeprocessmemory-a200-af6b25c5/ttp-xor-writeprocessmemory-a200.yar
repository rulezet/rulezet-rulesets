rule TTP_XOR_WriteProcessMemory_a200 {
  strings:
    $key_a200 = { f5 72 [2] c7 50 [2] c1 65 [2] ef 65 [2] d0 79 }

  condition:
    any of them
}