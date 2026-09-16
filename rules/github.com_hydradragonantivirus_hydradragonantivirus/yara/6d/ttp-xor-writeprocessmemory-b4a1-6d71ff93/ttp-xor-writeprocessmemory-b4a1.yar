rule TTP_XOR_WriteProcessMemory_b4a1 {
  strings:
    $key_b4a1 = { e3 d3 [2] d1 f1 [2] d7 c4 [2] f9 c4 [2] c6 d8 }

  condition:
    any of them
}