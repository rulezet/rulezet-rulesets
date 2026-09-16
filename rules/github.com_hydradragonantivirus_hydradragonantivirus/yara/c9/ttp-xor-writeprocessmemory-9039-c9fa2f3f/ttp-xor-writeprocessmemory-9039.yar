rule TTP_XOR_WriteProcessMemory_9039 {
  strings:
    $key_9039 = { c7 4b [2] f5 69 [2] f3 5c [2] dd 5c [2] e2 40 }

  condition:
    any of them
}