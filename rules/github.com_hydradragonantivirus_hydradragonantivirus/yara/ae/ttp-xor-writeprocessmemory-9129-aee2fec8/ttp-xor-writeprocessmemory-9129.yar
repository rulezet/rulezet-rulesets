rule TTP_XOR_WriteProcessMemory_9129 {
  strings:
    $key_9129 = { c6 5b [2] f4 79 [2] f2 4c [2] dc 4c [2] e3 50 }

  condition:
    any of them
}