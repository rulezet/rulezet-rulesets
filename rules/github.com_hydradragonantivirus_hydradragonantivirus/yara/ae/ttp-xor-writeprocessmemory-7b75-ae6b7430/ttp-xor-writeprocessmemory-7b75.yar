rule TTP_XOR_WriteProcessMemory_7b75 {
  strings:
    $key_7b75 = { 2c 07 [2] 1e 25 [2] 18 10 [2] 36 10 [2] 09 0c }

  condition:
    any of them
}