rule TTP_XOR_WriteProcessMemory_e7d3 {
  strings:
    $key_e7d3 = { b0 a1 [2] 82 83 [2] 84 b6 [2] aa b6 [2] 95 aa }

  condition:
    any of them
}