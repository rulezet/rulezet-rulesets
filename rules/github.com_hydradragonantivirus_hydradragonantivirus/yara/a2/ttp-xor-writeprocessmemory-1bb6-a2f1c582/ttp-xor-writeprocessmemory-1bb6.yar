rule TTP_XOR_WriteProcessMemory_1bb6 {
  strings:
    $key_1bb6 = { 4c c4 [2] 7e e6 [2] 78 d3 [2] 56 d3 [2] 69 cf }

  condition:
    any of them
}