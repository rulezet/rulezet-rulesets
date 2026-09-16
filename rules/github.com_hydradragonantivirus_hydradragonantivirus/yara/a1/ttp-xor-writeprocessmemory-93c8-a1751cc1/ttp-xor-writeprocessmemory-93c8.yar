rule TTP_XOR_WriteProcessMemory_93c8 {
  strings:
    $key_93c8 = { c4 ba [2] f6 98 [2] f0 ad [2] de ad [2] e1 b1 }

  condition:
    any of them
}