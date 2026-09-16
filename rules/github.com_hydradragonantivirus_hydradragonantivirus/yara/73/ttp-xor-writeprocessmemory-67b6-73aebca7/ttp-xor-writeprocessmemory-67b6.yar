rule TTP_XOR_WriteProcessMemory_67b6 {
  strings:
    $key_67b6 = { 30 c4 [2] 02 e6 [2] 04 d3 [2] 2a d3 [2] 15 cf }

  condition:
    any of them
}