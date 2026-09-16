rule TTP_XOR_WriteProcessMemory_6115 {
  strings:
    $key_6115 = { 36 67 [2] 04 45 [2] 02 70 [2] 2c 70 [2] 13 6c }

  condition:
    any of them
}