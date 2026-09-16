rule TTP_XOR_WriteProcessMemory_a253 {
  strings:
    $key_a253 = { f5 21 [2] c7 03 [2] c1 36 [2] ef 36 [2] d0 2a }

  condition:
    any of them
}