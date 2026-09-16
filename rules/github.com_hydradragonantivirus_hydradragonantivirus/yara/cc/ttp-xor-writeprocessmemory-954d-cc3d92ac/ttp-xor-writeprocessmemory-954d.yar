rule TTP_XOR_WriteProcessMemory_954d {
  strings:
    $key_954d = { c2 3f [2] f0 1d [2] f6 28 [2] d8 28 [2] e7 34 }

  condition:
    any of them
}