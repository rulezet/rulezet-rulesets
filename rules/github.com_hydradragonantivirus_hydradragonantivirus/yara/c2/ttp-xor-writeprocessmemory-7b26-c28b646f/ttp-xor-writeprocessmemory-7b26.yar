rule TTP_XOR_WriteProcessMemory_7b26 {
  strings:
    $key_7b26 = { 2c 54 [2] 1e 76 [2] 18 43 [2] 36 43 [2] 09 5f }

  condition:
    any of them
}