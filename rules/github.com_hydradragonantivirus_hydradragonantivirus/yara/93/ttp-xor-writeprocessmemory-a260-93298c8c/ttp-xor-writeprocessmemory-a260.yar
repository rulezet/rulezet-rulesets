rule TTP_XOR_WriteProcessMemory_a260 {
  strings:
    $key_a260 = { f5 12 [2] c7 30 [2] c1 05 [2] ef 05 [2] d0 19 }

  condition:
    any of them
}