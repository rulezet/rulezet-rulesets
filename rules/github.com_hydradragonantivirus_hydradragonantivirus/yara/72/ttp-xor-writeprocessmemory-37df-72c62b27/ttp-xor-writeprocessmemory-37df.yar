rule TTP_XOR_WriteProcessMemory_37df {
  strings:
    $key_37df = { 60 ad [2] 52 8f [2] 54 ba [2] 7a ba [2] 45 a6 }

  condition:
    any of them
}