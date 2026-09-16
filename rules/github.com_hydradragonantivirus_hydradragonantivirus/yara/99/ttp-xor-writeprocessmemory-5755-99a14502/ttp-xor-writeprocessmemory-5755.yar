rule TTP_XOR_WriteProcessMemory_5755 {
  strings:
    $key_5755 = { 00 27 [2] 32 05 [2] 34 30 [2] 1a 30 [2] 25 2c }

  condition:
    any of them
}