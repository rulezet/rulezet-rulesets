rule TTP_XOR_WriteProcessMemory_9752 {
  strings:
    $key_9752 = { c0 20 [2] f2 02 [2] f4 37 [2] da 37 [2] e5 2b }

  condition:
    any of them
}