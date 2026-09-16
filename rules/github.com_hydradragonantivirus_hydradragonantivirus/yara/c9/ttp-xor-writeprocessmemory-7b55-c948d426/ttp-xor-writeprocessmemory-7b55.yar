rule TTP_XOR_WriteProcessMemory_7b55 {
  strings:
    $key_7b55 = { 2c 27 [2] 1e 05 [2] 18 30 [2] 36 30 [2] 09 2c }

  condition:
    any of them
}