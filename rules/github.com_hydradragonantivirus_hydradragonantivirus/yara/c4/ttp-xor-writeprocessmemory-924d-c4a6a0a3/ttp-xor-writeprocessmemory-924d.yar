rule TTP_XOR_WriteProcessMemory_924d {
  strings:
    $key_924d = { c5 3f [2] f7 1d [2] f1 28 [2] df 28 [2] e0 34 }

  condition:
    any of them
}