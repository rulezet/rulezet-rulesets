rule TTP_XOR_WriteProcessMemory_a221 {
  strings:
    $key_a221 = { f5 53 [2] c7 71 [2] c1 44 [2] ef 44 [2] d0 58 }

  condition:
    any of them
}