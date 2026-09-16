rule TTP_XOR_WriteProcessMemory_9114 {
  strings:
    $key_9114 = { c6 66 [2] f4 44 [2] f2 71 [2] dc 71 [2] e3 6d }

  condition:
    any of them
}