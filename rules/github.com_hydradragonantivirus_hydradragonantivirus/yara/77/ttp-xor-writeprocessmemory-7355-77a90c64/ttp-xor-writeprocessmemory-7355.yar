rule TTP_XOR_WriteProcessMemory_7355 {
  strings:
    $key_7355 = { 24 27 [2] 16 05 [2] 10 30 [2] 3e 30 [2] 01 2c }

  condition:
    any of them
}