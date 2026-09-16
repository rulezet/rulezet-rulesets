rule TTP_XOR_WriteProcessMemory_a7b3 {
  strings:
    $key_a7b3 = { f0 c1 [2] c2 e3 [2] c4 d6 [2] ea d6 [2] d5 ca }

  condition:
    any of them
}