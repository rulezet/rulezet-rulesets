rule TTP_XOR_WriteProcessMemory_a146 {
  strings:
    $key_a146 = { f6 34 [2] c4 16 [2] c2 23 [2] ec 23 [2] d3 3f }

  condition:
    any of them
}