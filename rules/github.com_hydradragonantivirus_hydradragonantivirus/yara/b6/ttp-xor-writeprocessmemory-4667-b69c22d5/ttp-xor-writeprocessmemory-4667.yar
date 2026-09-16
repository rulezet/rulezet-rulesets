rule TTP_XOR_WriteProcessMemory_4667 {
  strings:
    $key_4667 = { 11 15 [2] 23 37 [2] 25 02 [2] 0b 02 [2] 34 1e }

  condition:
    any of them
}