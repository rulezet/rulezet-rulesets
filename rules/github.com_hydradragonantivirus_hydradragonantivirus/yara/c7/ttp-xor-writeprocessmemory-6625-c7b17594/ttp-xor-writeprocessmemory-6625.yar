rule TTP_XOR_WriteProcessMemory_6625 {
  strings:
    $key_6625 = { 31 57 [2] 03 75 [2] 05 40 [2] 2b 40 [2] 14 5c }

  condition:
    any of them
}