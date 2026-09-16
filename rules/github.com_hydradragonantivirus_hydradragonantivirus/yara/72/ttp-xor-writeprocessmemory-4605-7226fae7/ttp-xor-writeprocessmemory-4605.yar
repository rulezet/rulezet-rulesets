rule TTP_XOR_WriteProcessMemory_4605 {
  strings:
    $key_4605 = { 11 77 [2] 23 55 [2] 25 60 [2] 0b 60 [2] 34 7c }

  condition:
    any of them
}