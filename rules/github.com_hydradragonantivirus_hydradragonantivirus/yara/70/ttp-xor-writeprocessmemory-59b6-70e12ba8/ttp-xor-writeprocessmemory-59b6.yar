rule TTP_XOR_WriteProcessMemory_59b6 {
  strings:
    $key_59b6 = { 0e c4 [2] 3c e6 [2] 3a d3 [2] 14 d3 [2] 2b cf }

  condition:
    any of them
}