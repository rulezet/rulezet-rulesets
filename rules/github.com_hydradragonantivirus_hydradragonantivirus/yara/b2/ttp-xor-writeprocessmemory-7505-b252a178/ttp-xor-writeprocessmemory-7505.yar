rule TTP_XOR_WriteProcessMemory_7505 {
  strings:
    $key_7505 = { 22 77 [2] 10 55 [2] 16 60 [2] 38 60 [2] 07 7c }

  condition:
    any of them
}