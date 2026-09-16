rule TTP_XOR_WriteProcessMemory_7bdf {
  strings:
    $key_7bdf = { 2c ad [2] 1e 8f [2] 18 ba [2] 36 ba [2] 09 a6 }

  condition:
    any of them
}