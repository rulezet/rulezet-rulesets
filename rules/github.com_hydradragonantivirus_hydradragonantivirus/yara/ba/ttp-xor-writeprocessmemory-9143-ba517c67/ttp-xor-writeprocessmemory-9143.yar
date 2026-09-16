rule TTP_XOR_WriteProcessMemory_9143 {
  strings:
    $key_9143 = { c6 31 [2] f4 13 [2] f2 26 [2] dc 26 [2] e3 3a }

  condition:
    any of them
}