rule TTP_XOR_WriteProcessMemory_19df {
  strings:
    $key_19df = { 4e ad [2] 7c 8f [2] 7a ba [2] 54 ba [2] 6b a6 }

  condition:
    any of them
}