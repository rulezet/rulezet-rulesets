rule TTP_XOR_WriteProcessMemory_07df {
  strings:
    $key_07df = { 50 ad [2] 62 8f [2] 64 ba [2] 4a ba [2] 75 a6 }

  condition:
    any of them
}