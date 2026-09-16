rule TTP_XOR_WriteProcessMemory_853d {
  strings:
    $key_853d = { d2 4f [2] e0 6d [2] e6 58 [2] c8 58 [2] f7 44 }

  condition:
    any of them
}