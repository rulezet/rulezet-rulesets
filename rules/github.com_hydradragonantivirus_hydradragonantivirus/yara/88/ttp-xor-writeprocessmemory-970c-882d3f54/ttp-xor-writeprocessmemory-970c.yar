rule TTP_XOR_WriteProcessMemory_970c {
  strings:
    $key_970c = { c0 7e [2] f2 5c [2] f4 69 [2] da 69 [2] e5 75 }

  condition:
    any of them
}