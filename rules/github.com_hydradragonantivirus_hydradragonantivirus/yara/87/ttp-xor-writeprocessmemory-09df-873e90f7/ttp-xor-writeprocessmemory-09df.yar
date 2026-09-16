rule TTP_XOR_WriteProcessMemory_09df {
  strings:
    $key_09df = { 5e ad [2] 6c 8f [2] 6a ba [2] 44 ba [2] 7b a6 }

  condition:
    any of them
}