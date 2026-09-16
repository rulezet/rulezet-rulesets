rule TTP_XOR_WriteProcessMemory_866c {
  strings:
    $key_866c = { d1 1e [2] e3 3c [2] e5 09 [2] cb 09 [2] f4 15 }

  condition:
    any of them
}