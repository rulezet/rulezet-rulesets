rule TTP_XOR_WriteProcessMemory_7c55 {
  strings:
    $key_7c55 = { 2b 27 [2] 19 05 [2] 1f 30 [2] 31 30 [2] 0e 2c }

  condition:
    any of them
}