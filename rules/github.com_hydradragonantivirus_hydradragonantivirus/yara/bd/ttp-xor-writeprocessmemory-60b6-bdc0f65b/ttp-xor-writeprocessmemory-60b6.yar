rule TTP_XOR_WriteProcessMemory_60b6 {
  strings:
    $key_60b6 = { 37 c4 [2] 05 e6 [2] 03 d3 [2] 2d d3 [2] 12 cf }

  condition:
    any of them
}