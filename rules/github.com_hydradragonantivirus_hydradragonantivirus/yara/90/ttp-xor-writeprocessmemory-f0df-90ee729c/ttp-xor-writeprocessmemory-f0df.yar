rule TTP_XOR_WriteProcessMemory_f0df {
  strings:
    $key_f0df = { a7 ad [2] 95 8f [2] 93 ba [2] bd ba [2] 82 a6 }

  condition:
    any of them
}