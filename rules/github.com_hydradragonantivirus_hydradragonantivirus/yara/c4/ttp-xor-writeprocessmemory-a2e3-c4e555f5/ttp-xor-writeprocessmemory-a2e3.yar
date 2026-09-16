rule TTP_XOR_WriteProcessMemory_a2e3 {
  strings:
    $key_a2e3 = { f5 91 [2] c7 b3 [2] c1 86 [2] ef 86 [2] d0 9a }

  condition:
    any of them
}