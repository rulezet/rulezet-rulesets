rule TTP_XOR_WriteProcessMemory_a23d {
  strings:
    $key_a23d = { f5 4f [2] c7 6d [2] c1 58 [2] ef 58 [2] d0 44 }

  condition:
    any of them
}