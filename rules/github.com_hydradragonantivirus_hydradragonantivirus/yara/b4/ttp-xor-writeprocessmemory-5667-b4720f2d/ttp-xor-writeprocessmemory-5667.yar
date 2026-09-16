rule TTP_XOR_WriteProcessMemory_5667 {
  strings:
    $key_5667 = { 01 15 [2] 33 37 [2] 35 02 [2] 1b 02 [2] 24 1e }

  condition:
    any of them
}