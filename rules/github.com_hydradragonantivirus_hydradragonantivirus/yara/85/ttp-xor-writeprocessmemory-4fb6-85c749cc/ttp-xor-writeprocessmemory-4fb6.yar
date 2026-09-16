rule TTP_XOR_WriteProcessMemory_4fb6 {
  strings:
    $key_4fb6 = { 18 c4 [2] 2a e6 [2] 2c d3 [2] 02 d3 [2] 3d cf }

  condition:
    any of them
}