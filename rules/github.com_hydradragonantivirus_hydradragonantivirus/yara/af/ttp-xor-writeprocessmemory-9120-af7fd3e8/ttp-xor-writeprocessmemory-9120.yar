rule TTP_XOR_WriteProcessMemory_9120 {
  strings:
    $key_9120 = { c6 52 [2] f4 70 [2] f2 45 [2] dc 45 [2] e3 59 }

  condition:
    any of them
}