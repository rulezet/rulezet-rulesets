rule TTP_XOR_WriteProcessMemory_6555 {
  strings:
    $key_6555 = { 32 27 [2] 00 05 [2] 06 30 [2] 28 30 [2] 17 2c }

  condition:
    any of them
}