rule TTP_XOR_WriteProcessMemory_e4b6 {
  strings:
    $key_e4b6 = { b3 c4 [2] 81 e6 [2] 87 d3 [2] a9 d3 [2] 96 cf }

  condition:
    any of them
}