rule TTP_XOR_WriteProcessMemory_16df {
  strings:
    $key_16df = { 41 ad [2] 73 8f [2] 75 ba [2] 5b ba [2] 64 a6 }

  condition:
    any of them
}