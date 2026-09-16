rule TTP_XOR_WriteProcessMemory_91e0 {
  strings:
    $key_91e0 = { c6 92 [2] f4 b0 [2] f2 85 [2] dc 85 [2] e3 99 }

  condition:
    any of them
}