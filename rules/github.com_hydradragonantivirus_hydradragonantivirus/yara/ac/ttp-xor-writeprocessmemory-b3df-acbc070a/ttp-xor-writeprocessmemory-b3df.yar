rule TTP_XOR_WriteProcessMemory_b3df {
  strings:
    $key_b3df = { e4 ad [2] d6 8f [2] d0 ba [2] fe ba [2] c1 a6 }

  condition:
    any of them
}