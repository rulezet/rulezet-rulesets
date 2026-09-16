rule TTP_XOR_WriteProcessMemory_48df {
  strings:
    $key_48df = { 1f ad [2] 2d 8f [2] 2b ba [2] 05 ba [2] 3a a6 }

  condition:
    any of them
}