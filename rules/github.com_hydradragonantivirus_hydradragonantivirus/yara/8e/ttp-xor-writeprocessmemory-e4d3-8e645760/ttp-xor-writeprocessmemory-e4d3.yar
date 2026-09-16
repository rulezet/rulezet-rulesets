rule TTP_XOR_WriteProcessMemory_e4d3 {
  strings:
    $key_e4d3 = { b3 a1 [2] 81 83 [2] 87 b6 [2] a9 b6 [2] 96 aa }

  condition:
    any of them
}