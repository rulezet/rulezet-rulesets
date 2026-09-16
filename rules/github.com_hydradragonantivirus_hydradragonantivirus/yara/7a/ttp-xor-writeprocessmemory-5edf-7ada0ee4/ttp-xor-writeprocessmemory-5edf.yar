rule TTP_XOR_WriteProcessMemory_5edf {
  strings:
    $key_5edf = { 09 ad [2] 3b 8f [2] 3d ba [2] 13 ba [2] 2c a6 }

  condition:
    any of them
}