rule TTP_XOR_WriteProcessMemory_a271 {
  strings:
    $key_a271 = { f5 03 [2] c7 21 [2] c1 14 [2] ef 14 [2] d0 08 }

  condition:
    any of them
}