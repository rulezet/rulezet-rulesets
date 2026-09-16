rule TTP_XOR_WriteProcessMemory_0bb6 {
  strings:
    $key_0bb6 = { 5c c4 [2] 6e e6 [2] 68 d3 [2] 46 d3 [2] 79 cf }

  condition:
    any of them
}