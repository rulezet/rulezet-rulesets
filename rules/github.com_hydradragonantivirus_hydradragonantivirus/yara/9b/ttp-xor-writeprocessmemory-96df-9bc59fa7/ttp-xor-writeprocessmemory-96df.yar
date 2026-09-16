rule TTP_XOR_WriteProcessMemory_96df {
  strings:
    $key_96df = { c1 ad [2] f3 8f [2] f5 ba [2] db ba [2] e4 a6 }

  condition:
    any of them
}