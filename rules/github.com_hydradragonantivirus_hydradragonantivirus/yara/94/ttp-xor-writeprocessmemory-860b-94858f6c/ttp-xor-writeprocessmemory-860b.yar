rule TTP_XOR_WriteProcessMemory_860b {
  strings:
    $key_860b = { d1 79 [2] e3 5b [2] e5 6e [2] cb 6e [2] f4 72 }

  condition:
    any of them
}