rule TTP_XOR_WriteProcessMemory_9759 {
  strings:
    $key_9759 = { c0 2b [2] f2 09 [2] f4 3c [2] da 3c [2] e5 20 }

  condition:
    any of them
}