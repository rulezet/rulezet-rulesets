rule TTP_XOR_WriteProcessMemory_75df {
  strings:
    $key_75df = { 22 ad [2] 10 8f [2] 16 ba [2] 38 ba [2] 07 a6 }

  condition:
    any of them
}