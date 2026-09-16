rule TTP_XOR_WriteProcessMemory_4bb6 {
  strings:
    $key_4bb6 = { 1c c4 [2] 2e e6 [2] 28 d3 [2] 06 d3 [2] 39 cf }

  condition:
    any of them
}