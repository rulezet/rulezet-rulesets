rule TTP_XOR_WriteProcessMemory_4635 {
  strings:
    $key_4635 = { 11 47 [2] 23 65 [2] 25 50 [2] 0b 50 [2] 34 4c }

  condition:
    any of them
}