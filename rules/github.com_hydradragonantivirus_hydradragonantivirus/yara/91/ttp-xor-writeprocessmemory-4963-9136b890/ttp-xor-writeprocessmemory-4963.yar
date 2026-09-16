rule TTP_XOR_WriteProcessMemory_4963 {
  strings:
    $key_4963 = { 1e 11 [2] 2c 33 [2] 2a 06 [2] 04 06 [2] 3b 1a }

  condition:
    any of them
}