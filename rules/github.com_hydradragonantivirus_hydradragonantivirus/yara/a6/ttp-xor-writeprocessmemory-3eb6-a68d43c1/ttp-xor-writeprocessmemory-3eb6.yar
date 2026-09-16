rule TTP_XOR_WriteProcessMemory_3eb6 {
  strings:
    $key_3eb6 = { 69 c4 [2] 5b e6 [2] 5d d3 [2] 73 d3 [2] 4c cf }

  condition:
    any of them
}