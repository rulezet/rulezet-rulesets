rule TTP_XOR_WriteProcessMemory_7b36 {
  strings:
    $key_7b36 = { 2c 44 [2] 1e 66 [2] 18 53 [2] 36 53 [2] 09 4f }

  condition:
    any of them
}