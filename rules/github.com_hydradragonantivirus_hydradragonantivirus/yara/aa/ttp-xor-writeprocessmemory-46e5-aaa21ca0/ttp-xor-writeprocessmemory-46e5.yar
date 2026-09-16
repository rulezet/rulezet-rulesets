rule TTP_XOR_WriteProcessMemory_46e5 {
  strings:
    $key_46e5 = { 11 97 [2] 23 b5 [2] 25 80 [2] 0b 80 [2] 34 9c }

  condition:
    any of them
}