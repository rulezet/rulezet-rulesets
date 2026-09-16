rule TTP_XOR_WriteProcessMemory_3ae5 {
  strings:
    $key_3ae5 = { 6d 97 [2] 5f b5 [2] 59 80 [2] 77 80 [2] 48 9c }

  condition:
    any of them
}