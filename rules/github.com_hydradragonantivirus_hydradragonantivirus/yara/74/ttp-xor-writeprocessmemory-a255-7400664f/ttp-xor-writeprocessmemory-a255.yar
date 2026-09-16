rule TTP_XOR_WriteProcessMemory_a255 {
  strings:
    $key_a255 = { f5 27 [2] c7 05 [2] c1 30 [2] ef 30 [2] d0 2c }

  condition:
    any of them
}