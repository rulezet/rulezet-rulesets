rule TTP_XOR_WriteProcessMemory_a3df {
  strings:
    $key_a3df = { f4 ad [2] c6 8f [2] c0 ba [2] ee ba [2] d1 a6 }

  condition:
    any of them
}