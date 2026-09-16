rule TTP_XOR_WriteProcessMemory_850c {
  strings:
    $key_850c = { d2 7e [2] e0 5c [2] e6 69 [2] c8 69 [2] f7 75 }

  condition:
    any of them
}