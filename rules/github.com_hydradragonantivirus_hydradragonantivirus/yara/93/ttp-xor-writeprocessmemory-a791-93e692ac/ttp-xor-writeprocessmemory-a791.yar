rule TTP_XOR_WriteProcessMemory_a791 {
  strings:
    $key_a791 = { f0 e3 [2] c2 c1 [2] c4 f4 [2] ea f4 [2] d5 e8 }

  condition:
    any of them
}