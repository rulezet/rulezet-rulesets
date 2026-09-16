rule TTP_XOR_WriteProcessMemory_29df {
  strings:
    $key_29df = { 7e ad [2] 4c 8f [2] 4a ba [2] 64 ba [2] 5b a6 }

  condition:
    any of them
}