rule TTP_XOR_WriteProcessMemory_5adf {
  strings:
    $key_5adf = { 0d ad [2] 3f 8f [2] 39 ba [2] 17 ba [2] 28 a6 }

  condition:
    any of them
}