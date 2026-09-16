rule TTP_XOR_WriteProcessMemory_6655 {
  strings:
    $key_6655 = { 31 27 [2] 03 05 [2] 05 30 [2] 2b 30 [2] 14 2c }

  condition:
    any of them
}