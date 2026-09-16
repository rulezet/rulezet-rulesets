rule TTP_XOR_WriteProcessMemory_7b45 {
  strings:
    $key_7b45 = { 2c 37 [2] 1e 15 [2] 18 20 [2] 36 20 [2] 09 3c }

  condition:
    any of them
}