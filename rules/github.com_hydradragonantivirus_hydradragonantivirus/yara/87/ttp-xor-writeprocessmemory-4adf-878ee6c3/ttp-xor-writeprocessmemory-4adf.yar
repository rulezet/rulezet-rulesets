rule TTP_XOR_WriteProcessMemory_4adf {
  strings:
    $key_4adf = { 1d ad [2] 2f 8f [2] 29 ba [2] 07 ba [2] 38 a6 }

  condition:
    any of them
}