rule TTP_XOR_WriteProcessMemory_970d {
  strings:
    $key_970d = { c0 7f [2] f2 5d [2] f4 68 [2] da 68 [2] e5 74 }

  condition:
    any of them
}