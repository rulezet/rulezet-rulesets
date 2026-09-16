rule TTP_XOR_WriteProcessMemory_e1d3 {
  strings:
    $key_e1d3 = { b6 a1 [2] 84 83 [2] 82 b6 [2] ac b6 [2] 93 aa }

  condition:
    any of them
}