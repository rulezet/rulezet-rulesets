rule TTP_XOR_WriteProcessMemory_a5d3 {
  strings:
    $key_a5d3 = { f2 a1 [2] c0 83 [2] c6 b6 [2] e8 b6 [2] d7 aa }

  condition:
    any of them
}