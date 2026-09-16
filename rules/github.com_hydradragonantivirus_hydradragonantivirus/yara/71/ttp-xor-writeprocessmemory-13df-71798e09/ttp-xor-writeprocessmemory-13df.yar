rule TTP_XOR_WriteProcessMemory_13df {
  strings:
    $key_13df = { 44 ad [2] 76 8f [2] 70 ba [2] 5e ba [2] 61 a6 }

  condition:
    any of them
}