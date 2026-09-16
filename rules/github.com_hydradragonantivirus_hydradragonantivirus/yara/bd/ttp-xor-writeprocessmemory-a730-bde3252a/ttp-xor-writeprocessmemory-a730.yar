rule TTP_XOR_WriteProcessMemory_a730 {
  strings:
    $key_a730 = { f0 42 [2] c2 60 [2] c4 55 [2] ea 55 [2] d5 49 }

  condition:
    any of them
}