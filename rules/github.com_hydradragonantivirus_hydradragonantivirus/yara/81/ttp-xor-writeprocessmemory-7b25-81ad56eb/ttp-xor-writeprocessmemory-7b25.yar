rule TTP_XOR_WriteProcessMemory_7b25 {
  strings:
    $key_7b25 = { 2c 57 [2] 1e 75 [2] 18 40 [2] 36 40 [2] 09 5c }

  condition:
    any of them
}