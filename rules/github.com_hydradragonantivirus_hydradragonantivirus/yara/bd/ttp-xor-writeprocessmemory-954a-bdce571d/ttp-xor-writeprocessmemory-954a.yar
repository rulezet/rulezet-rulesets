rule TTP_XOR_WriteProcessMemory_954a {
  strings:
    $key_954a = { c2 38 [2] f0 1a [2] f6 2f [2] d8 2f [2] e7 33 }

  condition:
    any of them
}