rule TTP_XOR_WriteProcessMemory_b5df {
  strings:
    $key_b5df = { e2 ad [2] d0 8f [2] d6 ba [2] f8 ba [2] c7 a6 }

  condition:
    any of them
}