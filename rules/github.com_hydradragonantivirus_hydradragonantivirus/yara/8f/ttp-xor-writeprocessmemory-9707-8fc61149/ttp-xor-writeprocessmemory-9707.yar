rule TTP_XOR_WriteProcessMemory_9707 {
  strings:
    $key_9707 = { c0 75 [2] f2 57 [2] f4 62 [2] da 62 [2] e5 7e }

  condition:
    any of them
}