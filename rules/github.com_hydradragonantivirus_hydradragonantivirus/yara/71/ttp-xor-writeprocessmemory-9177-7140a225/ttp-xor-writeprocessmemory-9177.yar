rule TTP_XOR_WriteProcessMemory_9177 {
  strings:
    $key_9177 = { c6 05 [2] f4 27 [2] f2 12 [2] dc 12 [2] e3 0e }

  condition:
    any of them
}