rule TTP_XOR_WriteProcessMemory_3455 {
  strings:
    $key_3455 = { 63 27 [2] 51 05 [2] 57 30 [2] 79 30 [2] 46 2c }

  condition:
    any of them
}