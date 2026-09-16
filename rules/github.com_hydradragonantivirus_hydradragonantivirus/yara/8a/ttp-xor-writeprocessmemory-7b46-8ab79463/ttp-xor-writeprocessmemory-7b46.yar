rule TTP_XOR_WriteProcessMemory_7b46 {
  strings:
    $key_7b46 = { 2c 34 [2] 1e 16 [2] 18 23 [2] 36 23 [2] 09 3f }

  condition:
    any of them
}