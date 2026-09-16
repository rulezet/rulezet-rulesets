rule TTP_XOR_WriteProcessMemory_1805 {
  strings:
    $key_1805 = { 4f 77 [2] 7d 55 [2] 7b 60 [2] 55 60 [2] 6a 7c }

  condition:
    any of them
}