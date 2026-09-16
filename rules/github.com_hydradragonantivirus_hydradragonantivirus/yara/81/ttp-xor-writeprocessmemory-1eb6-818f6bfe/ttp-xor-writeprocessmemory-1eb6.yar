rule TTP_XOR_WriteProcessMemory_1eb6 {
  strings:
    $key_1eb6 = { 49 c4 [2] 7b e6 [2] 7d d3 [2] 53 d3 [2] 6c cf }

  condition:
    any of them
}