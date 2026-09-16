rule TTP_XOR_WriteProcessMemory_82c8 {
  strings:
    $key_82c8 = { d5 ba [2] e7 98 [2] e1 ad [2] cf ad [2] f0 b1 }

  condition:
    any of them
}