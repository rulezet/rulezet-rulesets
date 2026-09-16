rule TTP_XOR_WriteProcessMemory_53b6 {
  strings:
    $key_53b6 = { 04 c4 [2] 36 e6 [2] 30 d3 [2] 1e d3 [2] 21 cf }

  condition:
    any of them
}