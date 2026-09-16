rule TTP_XOR_WriteProcessMemory_1ddf {
  strings:
    $key_1ddf = { 4a ad [2] 78 8f [2] 7e ba [2] 50 ba [2] 6f a6 }

  condition:
    any of them
}