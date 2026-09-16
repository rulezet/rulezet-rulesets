rule TTP_XOR_WriteProcessMemory_3a45 {
  strings:
    $key_3a45 = { 6d 37 [2] 5f 15 [2] 59 20 [2] 77 20 [2] 48 3c }

  condition:
    any of them
}