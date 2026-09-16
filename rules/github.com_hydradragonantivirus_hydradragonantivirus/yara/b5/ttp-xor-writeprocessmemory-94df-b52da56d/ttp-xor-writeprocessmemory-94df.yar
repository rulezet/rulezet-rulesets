rule TTP_XOR_WriteProcessMemory_94df {
  strings:
    $key_94df = { c3 ad [2] f1 8f [2] f7 ba [2] d9 ba [2] e6 a6 }

  condition:
    any of them
}