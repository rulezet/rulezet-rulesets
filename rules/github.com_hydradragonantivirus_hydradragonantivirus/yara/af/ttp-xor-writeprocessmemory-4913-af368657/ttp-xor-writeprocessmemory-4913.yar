rule TTP_XOR_WriteProcessMemory_4913 {
  strings:
    $key_4913 = { 1e 61 [2] 2c 43 [2] 2a 76 [2] 04 76 [2] 3b 6a }

  condition:
    any of them
}