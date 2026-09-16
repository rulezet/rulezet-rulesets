rule TTP_XOR_WriteProcessMemory_9019 {
  strings:
    $key_9019 = { c7 6b [2] f5 49 [2] f3 7c [2] dd 7c [2] e2 60 }

  condition:
    any of them
}