rule TTP_XOR_WriteProcessMemory_5fb6 {
  strings:
    $key_5fb6 = { 08 c4 [2] 3a e6 [2] 3c d3 [2] 12 d3 [2] 2d cf }

  condition:
    any of them
}