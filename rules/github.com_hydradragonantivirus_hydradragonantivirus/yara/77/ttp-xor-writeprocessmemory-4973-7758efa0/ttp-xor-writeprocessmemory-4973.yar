rule TTP_XOR_WriteProcessMemory_4973 {
  strings:
    $key_4973 = { 1e 01 [2] 2c 23 [2] 2a 16 [2] 04 16 [2] 3b 0a }

  condition:
    any of them
}