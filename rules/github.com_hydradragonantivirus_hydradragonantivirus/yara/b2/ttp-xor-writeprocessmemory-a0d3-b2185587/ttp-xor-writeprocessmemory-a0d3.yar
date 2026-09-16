rule TTP_XOR_WriteProcessMemory_a0d3 {
  strings:
    $key_a0d3 = { f7 a1 [2] c5 83 [2] c3 b6 [2] ed b6 [2] d2 aa }

  condition:
    any of them
}