rule TTP_XOR_WriteProcessMemory_91c0 {
  strings:
    $key_91c0 = { c6 b2 [2] f4 90 [2] f2 a5 [2] dc a5 [2] e3 b9 }

  condition:
    any of them
}