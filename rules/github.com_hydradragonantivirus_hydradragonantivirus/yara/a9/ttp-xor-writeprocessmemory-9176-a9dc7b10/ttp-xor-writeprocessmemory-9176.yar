rule TTP_XOR_WriteProcessMemory_9176 {
  strings:
    $key_9176 = { c6 04 [2] f4 26 [2] f2 13 [2] dc 13 [2] e3 0f }

  condition:
    any of them
}