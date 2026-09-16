rule TTP_XOR_WriteProcessMemory_3a15 {
  strings:
    $key_3a15 = { 6d 67 [2] 5f 45 [2] 59 70 [2] 77 70 [2] 48 6c }

  condition:
    any of them
}