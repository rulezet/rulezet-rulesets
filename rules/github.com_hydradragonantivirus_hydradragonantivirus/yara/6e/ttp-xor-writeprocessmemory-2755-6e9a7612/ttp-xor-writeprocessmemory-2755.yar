rule TTP_XOR_WriteProcessMemory_2755 {
  strings:
    $key_2755 = { 70 27 [2] 42 05 [2] 44 30 [2] 6a 30 [2] 55 2c }

  condition:
    any of them
}