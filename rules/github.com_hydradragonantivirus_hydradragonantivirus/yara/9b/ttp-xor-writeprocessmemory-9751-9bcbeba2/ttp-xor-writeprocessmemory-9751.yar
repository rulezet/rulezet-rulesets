rule TTP_XOR_WriteProcessMemory_9751 {
  strings:
    $key_9751 = { c0 23 [2] f2 01 [2] f4 34 [2] da 34 [2] e5 28 }

  condition:
    any of them
}