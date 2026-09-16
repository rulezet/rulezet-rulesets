rule TTP_XOR_WriteProcessMemory_a208 {
  strings:
    $key_a208 = { f5 7a [2] c7 58 [2] c1 6d [2] ef 6d [2] d0 71 }

  condition:
    any of them
}