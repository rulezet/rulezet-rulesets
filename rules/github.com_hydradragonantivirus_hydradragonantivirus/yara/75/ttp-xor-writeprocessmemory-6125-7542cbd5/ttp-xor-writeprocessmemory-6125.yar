rule TTP_XOR_WriteProcessMemory_6125 {
  strings:
    $key_6125 = { 36 57 [2] 04 75 [2] 02 40 [2] 2c 40 [2] 13 5c }

  condition:
    any of them
}