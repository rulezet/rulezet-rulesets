rule TTP_XOR_WriteProcessMemory_65b6 {
  strings:
    $key_65b6 = { 32 c4 [2] 00 e6 [2] 06 d3 [2] 28 d3 [2] 17 cf }

  condition:
    any of them
}