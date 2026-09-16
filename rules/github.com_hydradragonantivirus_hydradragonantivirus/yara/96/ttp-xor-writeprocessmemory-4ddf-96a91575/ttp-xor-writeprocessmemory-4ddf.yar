rule TTP_XOR_WriteProcessMemory_4ddf {
  strings:
    $key_4ddf = { 1a ad [2] 28 8f [2] 2e ba [2] 00 ba [2] 3f a6 }

  condition:
    any of them
}