rule TTP_XOR_WriteProcessMemory_8568 {
  strings:
    $key_8568 = { d2 1a [2] e0 38 [2] e6 0d [2] c8 0d [2] f7 11 }

  condition:
    any of them
}