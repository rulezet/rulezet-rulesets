rule TTP_XOR_WriteProcessMemory_6755 {
  strings:
    $key_6755 = { 30 27 [2] 02 05 [2] 04 30 [2] 2a 30 [2] 15 2c }

  condition:
    any of them
}