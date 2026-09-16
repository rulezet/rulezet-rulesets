rule TTP_XOR_WriteProcessMemory_95df {
  strings:
    $key_95df = { c2 ad [2] f0 8f [2] f6 ba [2] d8 ba [2] e7 a6 }

  condition:
    any of them
}