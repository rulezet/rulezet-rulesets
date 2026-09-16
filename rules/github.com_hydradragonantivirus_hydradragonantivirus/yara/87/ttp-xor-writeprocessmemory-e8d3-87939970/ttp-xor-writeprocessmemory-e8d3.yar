rule TTP_XOR_WriteProcessMemory_e8d3 {
  strings:
    $key_e8d3 = { bf a1 [2] 8d 83 [2] 8b b6 [2] a5 b6 [2] 9a aa }

  condition:
    any of them
}