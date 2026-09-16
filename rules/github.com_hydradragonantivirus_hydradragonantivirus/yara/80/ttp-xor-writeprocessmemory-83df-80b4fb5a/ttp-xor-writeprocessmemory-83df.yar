rule TTP_XOR_WriteProcessMemory_83df {
  strings:
    $key_83df = { d4 ad [2] e6 8f [2] e0 ba [2] ce ba [2] f1 a6 }

  condition:
    any of them
}