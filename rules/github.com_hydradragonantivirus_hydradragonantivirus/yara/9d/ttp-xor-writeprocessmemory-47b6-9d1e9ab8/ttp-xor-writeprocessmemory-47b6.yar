rule TTP_XOR_WriteProcessMemory_47b6 {
  strings:
    $key_47b6 = { 10 c4 [2] 22 e6 [2] 24 d3 [2] 0a d3 [2] 35 cf }

  condition:
    any of them
}