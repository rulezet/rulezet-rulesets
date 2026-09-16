rule TTP_XOR_WriteProcessMemory_6765 {
  strings:
    $key_6765 = { 30 17 [2] 02 35 [2] 04 00 [2] 2a 00 [2] 15 1c }

  condition:
    any of them
}