rule TTP_XOR_WriteProcessMemory_a3d3 {
  strings:
    $key_a3d3 = { f4 a1 [2] c6 83 [2] c0 b6 [2] ee b6 [2] d1 aa }

  condition:
    any of them
}