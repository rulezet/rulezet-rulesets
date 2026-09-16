rule TTP_XOR_WriteProcessMemory_e0df {
  strings:
    $key_e0df = { b7 ad [2] 85 8f [2] 83 ba [2] ad ba [2] 92 a6 }

  condition:
    any of them
}