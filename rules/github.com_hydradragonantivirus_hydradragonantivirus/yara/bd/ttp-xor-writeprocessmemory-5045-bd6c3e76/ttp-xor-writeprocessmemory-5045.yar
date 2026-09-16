rule TTP_XOR_WriteProcessMemory_5045 {
  strings:
    $key_5045 = { 07 37 [2] 35 15 [2] 33 20 [2] 1d 20 [2] 22 3c }

  condition:
    any of them
}