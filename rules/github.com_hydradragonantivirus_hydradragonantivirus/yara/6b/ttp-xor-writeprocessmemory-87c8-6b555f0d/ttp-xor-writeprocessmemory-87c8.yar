rule TTP_XOR_WriteProcessMemory_87c8 {
  strings:
    $key_87c8 = { d0 ba [2] e2 98 [2] e4 ad [2] ca ad [2] f5 b1 }

  condition:
    any of them
}