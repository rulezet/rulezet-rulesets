rule TTP_XOR_WriteProcessMemory_a6a7 {
  strings:
    $key_a6a7 = { f1 d5 [2] c3 f7 [2] c5 c2 [2] eb c2 [2] d4 de }

  condition:
    any of them
}