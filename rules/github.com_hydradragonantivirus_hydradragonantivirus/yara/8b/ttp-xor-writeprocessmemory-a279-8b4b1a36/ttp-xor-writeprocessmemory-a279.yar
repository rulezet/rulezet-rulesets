rule TTP_XOR_WriteProcessMemory_a279 {
  strings:
    $key_a279 = { f5 0b [2] c7 29 [2] c1 1c [2] ef 1c [2] d0 00 }

  condition:
    any of them
}