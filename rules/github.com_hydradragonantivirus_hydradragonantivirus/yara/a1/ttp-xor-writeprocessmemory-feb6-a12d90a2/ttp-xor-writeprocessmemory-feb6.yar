rule TTP_XOR_WriteProcessMemory_feb6 {
  strings:
    $key_feb6 = { a9 c4 [2] 9b e6 [2] 9d d3 [2] b3 d3 [2] 8c cf }

  condition:
    any of them
}