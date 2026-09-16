rule TTP_XOR_WriteProcessMemory_e7df {
  strings:
    $key_e7df = { b0 ad [2] 82 8f [2] 84 ba [2] aa ba [2] 95 a6 }

  condition:
    any of them
}