rule TTP_XOR_WriteProcessMemory_22df {
  strings:
    $key_22df = { 75 ad [2] 47 8f [2] 41 ba [2] 6f ba [2] 50 a6 }

  condition:
    any of them
}