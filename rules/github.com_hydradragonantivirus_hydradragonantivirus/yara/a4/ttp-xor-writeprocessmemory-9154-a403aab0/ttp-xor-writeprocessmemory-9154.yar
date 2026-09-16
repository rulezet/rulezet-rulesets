rule TTP_XOR_WriteProcessMemory_9154 {
  strings:
    $key_9154 = { c6 26 [2] f4 04 [2] f2 31 [2] dc 31 [2] e3 2d }

  condition:
    any of them
}