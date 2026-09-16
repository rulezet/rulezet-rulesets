rule TTP_XOR_WriteProcessMemory_a2d3 {
  strings:
    $key_a2d3 = { f5 a1 [2] c7 83 [2] c1 b6 [2] ef b6 [2] d0 aa }

  condition:
    any of them
}