rule TTP_XOR_WriteProcessMemory_4305 {
  strings:
    $key_4305 = { 14 77 [2] 26 55 [2] 20 60 [2] 0e 60 [2] 31 7c }

  condition:
    any of them
}