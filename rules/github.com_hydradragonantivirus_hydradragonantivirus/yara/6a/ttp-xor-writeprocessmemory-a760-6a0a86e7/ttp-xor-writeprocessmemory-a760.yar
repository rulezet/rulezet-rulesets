rule TTP_XOR_WriteProcessMemory_a760 {
  strings:
    $key_a760 = { f0 12 [2] c2 30 [2] c4 05 [2] ea 05 [2] d5 19 }

  condition:
    any of them
}