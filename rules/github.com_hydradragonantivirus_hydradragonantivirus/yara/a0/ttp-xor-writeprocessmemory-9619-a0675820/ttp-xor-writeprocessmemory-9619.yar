rule TTP_XOR_WriteProcessMemory_9619 {
  strings:
    $key_9619 = { c1 6b [2] f3 49 [2] f5 7c [2] db 7c [2] e4 60 }

  condition:
    any of them
}