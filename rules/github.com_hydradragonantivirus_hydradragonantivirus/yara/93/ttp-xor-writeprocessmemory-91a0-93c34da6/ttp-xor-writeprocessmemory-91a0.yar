rule TTP_XOR_WriteProcessMemory_91a0 {
  strings:
    $key_91a0 = { c6 d2 [2] f4 f0 [2] f2 c5 [2] dc c5 [2] e3 d9 }

  condition:
    any of them
}