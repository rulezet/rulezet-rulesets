rule TTP_XOR_WriteProcessMemory_29b6 {
  strings:
    $key_29b6 = { 7e c4 [2] 4c e6 [2] 4a d3 [2] 64 d3 [2] 5b cf }

  condition:
    any of them
}