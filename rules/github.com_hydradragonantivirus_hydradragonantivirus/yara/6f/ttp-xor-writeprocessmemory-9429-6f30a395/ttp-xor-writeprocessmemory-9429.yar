rule TTP_XOR_WriteProcessMemory_9429 {
  strings:
    $key_9429 = { c3 5b [2] f1 79 [2] f7 4c [2] d9 4c [2] e6 50 }

  condition:
    any of them
}