rule TTP_XOR_WriteProcessMemory_a750 {
  strings:
    $key_a750 = { f0 22 [2] c2 00 [2] c4 35 [2] ea 35 [2] d5 29 }

  condition:
    any of them
}