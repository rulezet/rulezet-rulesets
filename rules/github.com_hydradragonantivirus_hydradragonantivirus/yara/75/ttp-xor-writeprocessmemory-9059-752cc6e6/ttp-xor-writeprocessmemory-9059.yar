rule TTP_XOR_WriteProcessMemory_9059 {
  strings:
    $key_9059 = { c7 2b [2] f5 09 [2] f3 3c [2] dd 3c [2] e2 20 }

  condition:
    any of them
}