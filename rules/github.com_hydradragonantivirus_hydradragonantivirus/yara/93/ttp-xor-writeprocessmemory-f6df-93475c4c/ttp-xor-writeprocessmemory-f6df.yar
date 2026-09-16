rule TTP_XOR_WriteProcessMemory_f6df {
  strings:
    $key_f6df = { a1 ad [2] 93 8f [2] 95 ba [2] bb ba [2] 84 a6 }

  condition:
    any of them
}