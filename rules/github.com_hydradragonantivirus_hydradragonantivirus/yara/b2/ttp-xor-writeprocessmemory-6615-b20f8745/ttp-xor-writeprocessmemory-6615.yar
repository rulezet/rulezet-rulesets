rule TTP_XOR_WriteProcessMemory_6615 {
  strings:
    $key_6615 = { 31 67 [2] 03 45 [2] 05 70 [2] 2b 70 [2] 14 6c }

  condition:
    any of them
}