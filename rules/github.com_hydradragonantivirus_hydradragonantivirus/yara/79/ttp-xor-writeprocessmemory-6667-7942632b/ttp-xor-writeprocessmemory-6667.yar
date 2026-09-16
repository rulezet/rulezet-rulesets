rule TTP_XOR_WriteProcessMemory_6667 {
  strings:
    $key_6667 = { 31 15 [2] 03 37 [2] 05 02 [2] 2b 02 [2] 14 1e }

  condition:
    any of them
}