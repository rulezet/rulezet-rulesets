rule TTP_XOR_WriteProcessMemory_60df {
  strings:
    $key_60df = { 37 ad [2] 05 8f [2] 03 ba [2] 2d ba [2] 12 a6 }

  condition:
    any of them
}