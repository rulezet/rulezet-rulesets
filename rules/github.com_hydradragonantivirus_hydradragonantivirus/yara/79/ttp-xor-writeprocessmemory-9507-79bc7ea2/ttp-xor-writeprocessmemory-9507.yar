rule TTP_XOR_WriteProcessMemory_9507 {
  strings:
    $key_9507 = { c2 75 [2] f0 57 [2] f6 62 [2] d8 62 [2] e7 7e }

  condition:
    any of them
}