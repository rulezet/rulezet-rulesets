rule TTP_XOR_WriteProcessMemory_3a25 {
  strings:
    $key_3a25 = { 6d 57 [2] 5f 75 [2] 59 40 [2] 77 40 [2] 48 5c }

  condition:
    any of them
}