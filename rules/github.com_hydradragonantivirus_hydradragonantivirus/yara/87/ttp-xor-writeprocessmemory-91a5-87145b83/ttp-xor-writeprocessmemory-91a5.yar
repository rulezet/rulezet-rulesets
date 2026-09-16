rule TTP_XOR_WriteProcessMemory_91a5 {
  strings:
    $key_91a5 = { c6 d7 [2] f4 f5 [2] f2 c0 [2] dc c0 [2] e3 dc }

  condition:
    any of them
}