rule TTP_XOR_WriteProcessMemory_a7f2 {
  strings:
    $key_a7f2 = { f0 80 [2] c2 a2 [2] c4 97 [2] ea 97 [2] d5 8b }

  condition:
    any of them
}