rule TTP_XOR_WriteProcessMemory_904d {
  strings:
    $key_904d = { c7 3f [2] f5 1d [2] f3 28 [2] dd 28 [2] e2 34 }

  condition:
    any of them
}