rule TTP_XOR_WriteProcessMemory_d5df {
  strings:
    $key_d5df = { 82 ad [2] b0 8f [2] b6 ba [2] 98 ba [2] a7 a6 }

  condition:
    any of them
}