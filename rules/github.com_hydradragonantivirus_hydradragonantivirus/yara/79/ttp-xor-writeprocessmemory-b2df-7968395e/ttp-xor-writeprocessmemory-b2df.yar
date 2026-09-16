rule TTP_XOR_WriteProcessMemory_b2df {
  strings:
    $key_b2df = { e5 ad [2] d7 8f [2] d1 ba [2] ff ba [2] c0 a6 }

  condition:
    any of them
}