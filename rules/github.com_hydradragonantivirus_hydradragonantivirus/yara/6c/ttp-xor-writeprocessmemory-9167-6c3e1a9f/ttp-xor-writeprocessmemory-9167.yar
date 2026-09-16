rule TTP_XOR_WriteProcessMemory_9167 {
  strings:
    $key_9167 = { c6 15 [2] f4 37 [2] f2 02 [2] dc 02 [2] e3 1e }

  condition:
    any of them
}