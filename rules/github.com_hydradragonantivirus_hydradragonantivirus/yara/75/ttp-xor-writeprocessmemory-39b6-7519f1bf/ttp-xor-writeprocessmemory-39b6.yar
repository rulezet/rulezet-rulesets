rule TTP_XOR_WriteProcessMemory_39b6 {
  strings:
    $key_39b6 = { 6e c4 [2] 5c e6 [2] 5a d3 [2] 74 d3 [2] 4b cf }

  condition:
    any of them
}