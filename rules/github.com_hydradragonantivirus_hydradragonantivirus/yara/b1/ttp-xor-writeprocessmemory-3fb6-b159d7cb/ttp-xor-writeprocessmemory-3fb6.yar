rule TTP_XOR_WriteProcessMemory_3fb6 {
  strings:
    $key_3fb6 = { 68 c4 [2] 5a e6 [2] 5c d3 [2] 72 d3 [2] 4d cf }

  condition:
    any of them
}