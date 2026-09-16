rule TTP_XOR_WriteProcessMemory_4c55 {
  strings:
    $key_4c55 = { 1b 27 [2] 29 05 [2] 2f 30 [2] 01 30 [2] 3e 2c }

  condition:
    any of them
}