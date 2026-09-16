rule TTP_XOR_WriteProcessMemory_7667 {
  strings:
    $key_7667 = { 21 15 [2] 13 37 [2] 15 02 [2] 3b 02 [2] 04 1e }

  condition:
    any of them
}