rule TTP_XOR_WriteProcessMemory_45df {
  strings:
    $key_45df = { 12 ad [2] 20 8f [2] 26 ba [2] 08 ba [2] 37 a6 }

  condition:
    any of them
}