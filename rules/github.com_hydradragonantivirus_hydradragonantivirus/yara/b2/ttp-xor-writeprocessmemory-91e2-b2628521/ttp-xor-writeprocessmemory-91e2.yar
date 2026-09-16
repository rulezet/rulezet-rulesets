rule TTP_XOR_WriteProcessMemory_91e2 {
  strings:
    $key_91e2 = { c6 90 [2] f4 b2 [2] f2 87 [2] dc 87 [2] e3 9b }

  condition:
    any of them
}