rule TTP_XOR_WriteProcessMemory_49b6 {
  strings:
    $key_49b6 = { 1e c4 [2] 2c e6 [2] 2a d3 [2] 04 d3 [2] 3b cf }

  condition:
    any of them
}