rule TTP_XOR_WriteProcessMemory_91c8 {
  strings:
    $key_91c8 = { c6 ba [2] f4 98 [2] f2 ad [2] dc ad [2] e3 b1 }

  condition:
    any of them
}