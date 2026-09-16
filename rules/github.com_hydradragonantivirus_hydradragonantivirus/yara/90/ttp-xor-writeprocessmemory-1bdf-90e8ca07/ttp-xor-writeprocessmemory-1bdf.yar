rule TTP_XOR_WriteProcessMemory_1bdf {
  strings:
    $key_1bdf = { 4c ad [2] 7e 8f [2] 78 ba [2] 56 ba [2] 69 a6 }

  condition:
    any of them
}