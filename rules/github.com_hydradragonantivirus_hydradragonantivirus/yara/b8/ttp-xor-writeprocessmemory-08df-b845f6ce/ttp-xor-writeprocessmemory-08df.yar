rule TTP_XOR_WriteProcessMemory_08df {
  strings:
    $key_08df = { 5f ad [2] 6d 8f [2] 6b ba [2] 45 ba [2] 7a a6 }

  condition:
    any of them
}