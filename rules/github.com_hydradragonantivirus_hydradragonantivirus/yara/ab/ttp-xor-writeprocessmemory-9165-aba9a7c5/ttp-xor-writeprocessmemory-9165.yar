rule TTP_XOR_WriteProcessMemory_9165 {
  strings:
    $key_9165 = { c6 17 [2] f4 35 [2] f2 00 [2] dc 00 [2] e3 1c }

  condition:
    any of them
}