rule TTP_XOR_WriteProcessMemory_20df {
  strings:
    $key_20df = { 77 ad [2] 45 8f [2] 43 ba [2] 6d ba [2] 52 a6 }

  condition:
    any of them
}