rule TTP_XOR_WriteProcessMemory_e0b6 {
  strings:
    $key_e0b6 = { b7 c4 [2] 85 e6 [2] 83 d3 [2] ad d3 [2] 92 cf }

  condition:
    any of them
}