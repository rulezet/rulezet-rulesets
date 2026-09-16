rule TTP_XOR_WriteProcessMemory_e5df {
  strings:
    $key_e5df = { b2 ad [2] 80 8f [2] 86 ba [2] a8 ba [2] 97 a6 }

  condition:
    any of them
}