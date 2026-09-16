rule TTP_XOR_WriteProcessMemory_a4a7 {
  strings:
    $key_a4a7 = { f3 d5 [2] c1 f7 [2] c7 c2 [2] e9 c2 [2] d6 de }

  condition:
    any of them
}