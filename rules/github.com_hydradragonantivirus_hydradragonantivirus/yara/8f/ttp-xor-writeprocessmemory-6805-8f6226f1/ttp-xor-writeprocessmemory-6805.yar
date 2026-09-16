rule TTP_XOR_WriteProcessMemory_6805 {
  strings:
    $key_6805 = { 3f 77 [2] 0d 55 [2] 0b 60 [2] 25 60 [2] 1a 7c }

  condition:
    any of them
}