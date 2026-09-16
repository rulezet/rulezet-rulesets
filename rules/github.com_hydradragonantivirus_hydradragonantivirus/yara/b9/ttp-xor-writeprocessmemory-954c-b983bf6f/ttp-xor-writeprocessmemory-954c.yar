rule TTP_XOR_WriteProcessMemory_954c {
  strings:
    $key_954c = { c2 3e [2] f0 1c [2] f6 29 [2] d8 29 [2] e7 35 }

  condition:
    any of them
}