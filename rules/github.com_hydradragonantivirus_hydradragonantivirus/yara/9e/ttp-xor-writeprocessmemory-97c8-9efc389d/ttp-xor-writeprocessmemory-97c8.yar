rule TTP_XOR_WriteProcessMemory_97c8 {
  strings:
    $key_97c8 = { c0 ba [2] f2 98 [2] f4 ad [2] da ad [2] e5 b1 }

  condition:
    any of them
}