rule TTP_XOR_WriteProcessMemory_57df {
  strings:
    $key_57df = { 00 ad [2] 32 8f [2] 34 ba [2] 1a ba [2] 25 a6 }

  condition:
    any of them
}