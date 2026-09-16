rule TTP_XOR_WriteProcessMemory_950c {
  strings:
    $key_950c = { c2 7e [2] f0 5c [2] f6 69 [2] d8 69 [2] e7 75 }

  condition:
    any of them
}