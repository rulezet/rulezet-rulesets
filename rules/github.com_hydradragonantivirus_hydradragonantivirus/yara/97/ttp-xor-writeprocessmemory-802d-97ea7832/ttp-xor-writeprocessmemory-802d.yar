rule TTP_XOR_WriteProcessMemory_802d {
  strings:
    $key_802d = { d7 5f [2] e5 7d [2] e3 48 [2] cd 48 [2] f2 54 }

  condition:
    any of them
}