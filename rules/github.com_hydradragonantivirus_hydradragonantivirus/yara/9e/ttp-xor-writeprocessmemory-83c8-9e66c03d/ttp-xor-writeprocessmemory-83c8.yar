rule TTP_XOR_WriteProcessMemory_83c8 {
  strings:
    $key_83c8 = { d4 ba [2] e6 98 [2] e0 ad [2] ce ad [2] f1 b1 }

  condition:
    any of them
}