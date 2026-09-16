rule TTP_XOR_WriteProcessMemory_a9d3 {
  strings:
    $key_a9d3 = { fe a1 [2] cc 83 [2] ca b6 [2] e4 b6 [2] db aa }

  condition:
    any of them
}