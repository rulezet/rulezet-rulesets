rule TTP_XOR_WriteProcessMemory_b7df {
  strings:
    $key_b7df = { e0 ad [2] d2 8f [2] d4 ba [2] fa ba [2] c5 a6 }

  condition:
    any of them
}