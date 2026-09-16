rule TTP_XOR_WriteProcessMemory_977d {
  strings:
    $key_977d = { c0 0f [2] f2 2d [2] f4 18 [2] da 18 [2] e5 04 }

  condition:
    any of them
}