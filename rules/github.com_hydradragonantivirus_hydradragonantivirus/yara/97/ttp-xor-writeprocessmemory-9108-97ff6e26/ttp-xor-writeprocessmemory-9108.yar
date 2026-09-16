rule TTP_XOR_WriteProcessMemory_9108 {
  strings:
    $key_9108 = { c6 7a [2] f4 58 [2] f2 6d [2] dc 6d [2] e3 71 }

  condition:
    any of them
}