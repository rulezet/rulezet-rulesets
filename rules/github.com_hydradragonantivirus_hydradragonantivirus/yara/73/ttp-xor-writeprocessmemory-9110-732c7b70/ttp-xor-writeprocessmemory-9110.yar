rule TTP_XOR_WriteProcessMemory_9110 {
  strings:
    $key_9110 = { c6 62 [2] f4 40 [2] f2 75 [2] dc 75 [2] e3 69 }

  condition:
    any of them
}