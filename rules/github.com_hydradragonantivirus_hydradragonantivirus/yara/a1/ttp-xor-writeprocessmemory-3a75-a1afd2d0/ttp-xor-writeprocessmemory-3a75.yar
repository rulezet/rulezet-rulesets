rule TTP_XOR_WriteProcessMemory_3a75 {
  strings:
    $key_3a75 = { 6d 07 [2] 5f 25 [2] 59 10 [2] 77 10 [2] 48 0c }

  condition:
    any of them
}