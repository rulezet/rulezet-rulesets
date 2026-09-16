rule TTP_XOR_WriteProcessMemory_866b {
  strings:
    $key_866b = { d1 19 [2] e3 3b [2] e5 0e [2] cb 0e [2] f4 12 }

  condition:
    any of them
}