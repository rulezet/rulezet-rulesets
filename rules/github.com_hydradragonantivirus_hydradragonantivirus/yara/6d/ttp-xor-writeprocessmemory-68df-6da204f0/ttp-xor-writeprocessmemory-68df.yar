rule TTP_XOR_WriteProcessMemory_68df {
  strings:
    $key_68df = { 3f ad [2] 0d 8f [2] 0b ba [2] 25 ba [2] 1a a6 }

  condition:
    any of them
}