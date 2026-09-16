rule TTP_XOR_WriteProcessMemory_9705 {
  strings:
    $key_9705 = { c0 77 [2] f2 55 [2] f4 60 [2] da 60 [2] e5 7c }

  condition:
    any of them
}