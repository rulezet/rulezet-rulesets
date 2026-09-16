rule TTP_XOR_WriteProcessMemory_91df {
  strings:
    $key_91df = { c6 ad [2] f4 8f [2] f2 ba [2] dc ba [2] e3 a6 }

  condition:
    any of them
}