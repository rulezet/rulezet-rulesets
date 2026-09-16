rule TTP_XOR_WriteProcessMemory_c4df {
  strings:
    $key_c4df = { 93 ad [2] a1 8f [2] a7 ba [2] 89 ba [2] b6 a6 }

  condition:
    any of them
}