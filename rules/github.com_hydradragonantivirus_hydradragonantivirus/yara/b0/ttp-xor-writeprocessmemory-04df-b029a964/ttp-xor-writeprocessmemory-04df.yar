rule TTP_XOR_WriteProcessMemory_04df {
  strings:
    $key_04df = { 53 ad [2] 61 8f [2] 67 ba [2] 49 ba [2] 76 a6 }

  condition:
    any of them
}