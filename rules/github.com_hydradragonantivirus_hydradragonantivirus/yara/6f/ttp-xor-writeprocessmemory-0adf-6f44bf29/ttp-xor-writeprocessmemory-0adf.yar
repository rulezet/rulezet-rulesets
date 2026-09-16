rule TTP_XOR_WriteProcessMemory_0adf {
  strings:
    $key_0adf = { 5d ad [2] 6f 8f [2] 69 ba [2] 47 ba [2] 78 a6 }

  condition:
    any of them
}