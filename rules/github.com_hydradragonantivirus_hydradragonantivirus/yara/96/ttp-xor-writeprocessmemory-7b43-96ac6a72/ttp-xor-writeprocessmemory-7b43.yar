rule TTP_XOR_WriteProcessMemory_7b43 {
  strings:
    $key_7b43 = { 2c 31 [2] 1e 13 [2] 18 26 [2] 36 26 [2] 09 3a }

  condition:
    any of them
}