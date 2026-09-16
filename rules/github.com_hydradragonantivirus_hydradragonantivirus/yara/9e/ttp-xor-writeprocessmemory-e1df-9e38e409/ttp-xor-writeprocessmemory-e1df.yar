rule TTP_XOR_WriteProcessMemory_e1df {
  strings:
    $key_e1df = { b6 ad [2] 84 8f [2] 82 ba [2] ac ba [2] 93 a6 }

  condition:
    any of them
}