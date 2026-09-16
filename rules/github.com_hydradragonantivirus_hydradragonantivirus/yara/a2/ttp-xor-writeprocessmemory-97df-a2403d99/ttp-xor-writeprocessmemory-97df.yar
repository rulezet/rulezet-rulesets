rule TTP_XOR_WriteProcessMemory_97df {
  strings:
    $key_97df = { c0 ad [2] f2 8f [2] f4 ba [2] da ba [2] e5 a6 }

  condition:
    any of them
}