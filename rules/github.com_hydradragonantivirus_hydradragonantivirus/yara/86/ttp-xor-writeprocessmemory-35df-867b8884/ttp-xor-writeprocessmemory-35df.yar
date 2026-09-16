rule TTP_XOR_WriteProcessMemory_35df {
  strings:
    $key_35df = { 62 ad [2] 50 8f [2] 56 ba [2] 78 ba [2] 47 a6 }

  condition:
    any of them
}