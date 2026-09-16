rule TTP_XOR_WriteProcessMemory_5c55 {
  strings:
    $key_5c55 = { 0b 27 [2] 39 05 [2] 3f 30 [2] 11 30 [2] 2e 2c }

  condition:
    any of them
}