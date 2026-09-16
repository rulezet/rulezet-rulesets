rule TTP_XOR_WriteProcessMemory_f7d3 {
  strings:
    $key_f7d3 = { a0 a1 [2] 92 83 [2] 94 b6 [2] ba b6 [2] 85 aa }

  condition:
    any of them
}