rule TTP_XOR_WriteProcessMemory_7715 {
  strings:
    $key_7715 = { 20 67 [2] 12 45 [2] 14 70 [2] 3a 70 [2] 05 6c }

  condition:
    any of them
}