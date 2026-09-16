rule TTP_XOR_WriteProcessMemory_3bdf {
  strings:
    $key_3bdf = { 6c ad [2] 5e 8f [2] 58 ba [2] 76 ba [2] 49 a6 }

  condition:
    any of them
}