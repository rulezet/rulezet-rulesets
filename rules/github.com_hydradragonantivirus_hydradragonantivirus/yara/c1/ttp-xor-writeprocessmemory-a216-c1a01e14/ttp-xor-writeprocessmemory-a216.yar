rule TTP_XOR_WriteProcessMemory_a216 {
  strings:
    $key_a216 = { f5 64 [2] c7 46 [2] c1 73 [2] ef 73 [2] d0 6f }

  condition:
    any of them
}