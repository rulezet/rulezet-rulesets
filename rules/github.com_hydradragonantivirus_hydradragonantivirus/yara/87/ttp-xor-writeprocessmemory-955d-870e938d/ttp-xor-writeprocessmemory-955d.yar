rule TTP_XOR_WriteProcessMemory_955d {
  strings:
    $key_955d = { c2 2f [2] f0 0d [2] f6 38 [2] d8 38 [2] e7 24 }

  condition:
    any of them
}