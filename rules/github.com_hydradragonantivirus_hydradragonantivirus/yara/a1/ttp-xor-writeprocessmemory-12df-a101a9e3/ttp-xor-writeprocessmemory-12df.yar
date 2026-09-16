rule TTP_XOR_WriteProcessMemory_12df {
  strings:
    $key_12df = { 45 ad [2] 77 8f [2] 71 ba [2] 5f ba [2] 60 a6 }

  condition:
    any of them
}