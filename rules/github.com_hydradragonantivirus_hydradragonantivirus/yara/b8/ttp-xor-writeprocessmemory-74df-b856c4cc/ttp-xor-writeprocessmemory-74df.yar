rule TTP_XOR_WriteProcessMemory_74df {
  strings:
    $key_74df = { 23 ad [2] 11 8f [2] 17 ba [2] 39 ba [2] 06 a6 }

  condition:
    any of them
}