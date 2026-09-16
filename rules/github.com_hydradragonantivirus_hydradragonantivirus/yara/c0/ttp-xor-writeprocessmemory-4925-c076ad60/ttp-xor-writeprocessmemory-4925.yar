rule TTP_XOR_WriteProcessMemory_4925 {
  strings:
    $key_4925 = { 1e 57 [2] 2c 75 [2] 2a 40 [2] 04 40 [2] 3b 5c }

  condition:
    any of them
}