rule TTP_XOR_WriteProcessMemory_1375 {
  strings:
    $key_1375 = { 44 07 [2] 76 25 [2] 70 10 [2] 5e 10 [2] 61 0c }

  condition:
    any of them
}