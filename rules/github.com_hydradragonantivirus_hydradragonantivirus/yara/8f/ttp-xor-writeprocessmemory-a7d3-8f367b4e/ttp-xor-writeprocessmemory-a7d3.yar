rule TTP_XOR_WriteProcessMemory_a7d3 {
  strings:
    $key_a7d3 = { f0 a1 [2] c2 83 [2] c4 b6 [2] ea b6 [2] d5 aa }

  condition:
    any of them
}