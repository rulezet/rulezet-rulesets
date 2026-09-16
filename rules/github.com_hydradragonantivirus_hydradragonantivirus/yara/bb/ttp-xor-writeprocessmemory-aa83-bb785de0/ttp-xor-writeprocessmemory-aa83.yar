rule TTP_XOR_WriteProcessMemory_aa83 {
  strings:
    $key_aa83 = { fd f1 [2] cf d3 [2] c9 e6 [2] e7 e6 [2] d8 fa }

  condition:
    any of them
}