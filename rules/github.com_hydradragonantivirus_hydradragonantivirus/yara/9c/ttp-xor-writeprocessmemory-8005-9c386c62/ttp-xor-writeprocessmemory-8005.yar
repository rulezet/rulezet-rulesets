rule TTP_XOR_WriteProcessMemory_8005 {
  strings:
    $key_8005 = { d7 77 [2] e5 55 [2] e3 60 [2] cd 60 [2] f2 7c }

  condition:
    any of them
}