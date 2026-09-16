rule TTP_XOR_WriteProcessMemory_7b73 {
  strings:
    $key_7b73 = { 2c 01 [2] 1e 23 [2] 18 16 [2] 36 16 [2] 09 0a }

  condition:
    any of them
}