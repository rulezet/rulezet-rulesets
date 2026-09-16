rule TTP_XOR_WriteProcessMemory_6bdf {
  strings:
    $key_6bdf = { 3c ad [2] 0e 8f [2] 08 ba [2] 26 ba [2] 19 a6 }

  condition:
    any of them
}