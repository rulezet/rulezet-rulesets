rule TTP_XOR_WriteProcessMemory_7605 {
  strings:
    $key_7605 = { 21 77 [2] 13 55 [2] 15 60 [2] 3b 60 [2] 04 7c }

  condition:
    any of them
}