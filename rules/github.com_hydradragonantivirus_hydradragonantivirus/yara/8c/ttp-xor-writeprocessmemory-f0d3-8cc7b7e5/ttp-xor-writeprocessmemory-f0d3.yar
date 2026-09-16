rule TTP_XOR_WriteProcessMemory_f0d3 {
  strings:
    $key_f0d3 = { a7 a1 [2] 95 83 [2] 93 b6 [2] bd b6 [2] 82 aa }

  condition:
    any of them
}