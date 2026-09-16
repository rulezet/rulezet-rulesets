rule TTP_XOR_WriteProcessMemory_7343 {
  strings:
    $key_7343 = { 24 31 [2] 16 13 [2] 10 26 [2] 3e 26 [2] 01 3a }

  condition:
    any of them
}