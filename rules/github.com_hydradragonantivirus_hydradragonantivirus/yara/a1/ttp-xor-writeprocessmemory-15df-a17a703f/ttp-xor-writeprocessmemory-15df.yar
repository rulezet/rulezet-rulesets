rule TTP_XOR_WriteProcessMemory_15df {
  strings:
    $key_15df = { 42 ad [2] 70 8f [2] 76 ba [2] 58 ba [2] 67 a6 }

  condition:
    any of them
}