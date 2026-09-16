rule TTP_XOR_WriteProcessMemory_6eb6 {
  strings:
    $key_6eb6 = { 39 c4 [2] 0b e6 [2] 0d d3 [2] 23 d3 [2] 1c cf }

  condition:
    any of them
}