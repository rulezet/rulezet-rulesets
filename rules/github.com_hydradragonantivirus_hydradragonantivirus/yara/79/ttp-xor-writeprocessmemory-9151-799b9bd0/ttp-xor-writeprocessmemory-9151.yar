rule TTP_XOR_WriteProcessMemory_9151 {
  strings:
    $key_9151 = { c6 23 [2] f4 01 [2] f2 34 [2] dc 34 [2] e3 28 }

  condition:
    any of them
}