rule TTP_XOR_WriteProcessMemory_2c55 {
  strings:
    $key_2c55 = { 7b 27 [2] 49 05 [2] 4f 30 [2] 61 30 [2] 5e 2c }

  condition:
    any of them
}