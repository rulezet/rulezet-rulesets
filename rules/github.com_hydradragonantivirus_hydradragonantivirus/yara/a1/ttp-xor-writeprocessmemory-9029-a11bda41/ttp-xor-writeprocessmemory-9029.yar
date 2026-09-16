rule TTP_XOR_WriteProcessMemory_9029 {
  strings:
    $key_9029 = { c7 5b [2] f5 79 [2] f3 4c [2] dd 4c [2] e2 50 }

  condition:
    any of them
}