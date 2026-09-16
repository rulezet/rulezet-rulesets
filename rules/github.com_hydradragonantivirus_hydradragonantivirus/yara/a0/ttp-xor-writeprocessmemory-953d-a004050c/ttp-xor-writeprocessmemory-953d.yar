rule TTP_XOR_WriteProcessMemory_953d {
  strings:
    $key_953d = { c2 4f [2] f0 6d [2] f6 58 [2] d8 58 [2] e7 44 }

  condition:
    any of them
}