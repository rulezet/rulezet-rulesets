rule TTP_XOR_WriteProcessMemory_9609 {
  strings:
    $key_9609 = { c1 7b [2] f3 59 [2] f5 6c [2] db 6c [2] e4 70 }

  condition:
    any of them
}