rule TTP_XOR_WriteProcessMemory_91a4 {
  strings:
    $key_91a4 = { c6 d6 [2] f4 f4 [2] f2 c1 [2] dc c1 [2] e3 dd }

  condition:
    any of them
}