rule TTP_XOR_WriteProcessMemory_9166 {
  strings:
    $key_9166 = { c6 14 [2] f4 36 [2] f2 03 [2] dc 03 [2] e3 1f }

  condition:
    any of them
}