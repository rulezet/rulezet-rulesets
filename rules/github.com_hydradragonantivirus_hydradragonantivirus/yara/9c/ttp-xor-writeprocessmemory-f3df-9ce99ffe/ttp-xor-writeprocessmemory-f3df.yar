rule TTP_XOR_WriteProcessMemory_f3df {
  strings:
    $key_f3df = { a4 ad [2] 96 8f [2] 90 ba [2] be ba [2] 81 a6 }

  condition:
    any of them
}