rule TTP_XOR_WriteProcessMemory_0bdf {
  strings:
    $key_0bdf = { 5c ad [2] 6e 8f [2] 68 ba [2] 46 ba [2] 79 a6 }

  condition:
    any of them
}