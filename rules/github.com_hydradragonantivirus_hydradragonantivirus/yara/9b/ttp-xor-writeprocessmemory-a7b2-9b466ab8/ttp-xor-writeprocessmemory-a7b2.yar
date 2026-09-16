rule TTP_XOR_WriteProcessMemory_a7b2 {
  strings:
    $key_a7b2 = { f0 c0 [2] c2 e2 [2] c4 d7 [2] ea d7 [2] d5 cb }

  condition:
    any of them
}