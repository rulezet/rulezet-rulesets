rule TTP_XOR_WriteProcessMemory_9005 {
  strings:
    $key_9005 = { c7 77 [2] f5 55 [2] f3 60 [2] dd 60 [2] e2 7c }

  condition:
    any of them
}