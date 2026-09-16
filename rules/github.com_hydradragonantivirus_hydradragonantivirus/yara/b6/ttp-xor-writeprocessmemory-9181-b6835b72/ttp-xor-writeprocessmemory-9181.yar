rule TTP_XOR_WriteProcessMemory_9181 {
  strings:
    $key_9181 = { c6 f3 [2] f4 d1 [2] f2 e4 [2] dc e4 [2] e3 f8 }

  condition:
    any of them
}