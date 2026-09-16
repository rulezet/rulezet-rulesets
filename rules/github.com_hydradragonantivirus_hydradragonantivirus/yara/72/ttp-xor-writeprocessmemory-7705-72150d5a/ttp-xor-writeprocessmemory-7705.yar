rule TTP_XOR_WriteProcessMemory_7705 {
  strings:
    $key_7705 = { 20 77 [2] 12 55 [2] 14 60 [2] 3a 60 [2] 05 7c }

  condition:
    any of them
}