rule TTP_XOR_WriteProcessMemory_3555 {
  strings:
    $key_3555 = { 62 27 [2] 50 05 [2] 56 30 [2] 78 30 [2] 47 2c }

  condition:
    any of them
}