rule TTP_XOR_WriteProcessMemory_1fb6 {
  strings:
    $key_1fb6 = { 48 c4 [2] 7a e6 [2] 7c d3 [2] 52 d3 [2] 6d cf }

  condition:
    any of them
}