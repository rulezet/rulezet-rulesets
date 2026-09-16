rule TTP_XOR_WriteProcessMemory_9519 {
  strings:
    $key_9519 = { c2 6b [2] f0 49 [2] f6 7c [2] d8 7c [2] e7 60 }

  condition:
    any of them
}