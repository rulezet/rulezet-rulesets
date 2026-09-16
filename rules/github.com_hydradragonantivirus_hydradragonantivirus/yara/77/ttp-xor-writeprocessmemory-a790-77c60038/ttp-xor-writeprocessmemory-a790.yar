rule TTP_XOR_WriteProcessMemory_a790 {
  strings:
    $key_a790 = { f0 e2 [2] c2 c0 [2] c4 f5 [2] ea f5 [2] d5 e9 }

  condition:
    any of them
}