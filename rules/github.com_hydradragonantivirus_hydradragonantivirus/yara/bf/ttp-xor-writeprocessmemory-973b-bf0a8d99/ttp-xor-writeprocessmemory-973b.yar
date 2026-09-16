rule TTP_XOR_WriteProcessMemory_973b {
  strings:
    $key_973b = { c0 49 [2] f2 6b [2] f4 5e [2] da 5e [2] e5 42 }

  condition:
    any of them
}