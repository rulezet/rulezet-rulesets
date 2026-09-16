rule TTP_XOR_WriteProcessMemory_91e6 {
  strings:
    $key_91e6 = { c6 94 [2] f4 b6 [2] f2 83 [2] dc 83 [2] e3 9f }

  condition:
    any of them
}