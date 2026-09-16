rule TTP_XOR_WriteProcessMemory_802b {
  strings:
    $key_802b = { d7 59 [2] e5 7b [2] e3 4e [2] cd 4e [2] f2 52 }

  condition:
    any of them
}