rule TTP_XOR_WriteProcessMemory_d6df {
  strings:
    $key_d6df = { 81 ad [2] b3 8f [2] b5 ba [2] 9b ba [2] a4 a6 }

  condition:
    any of them
}