rule TTP_XOR_WriteProcessMemory_2bdf {
  strings:
    $key_2bdf = { 7c ad [2] 4e 8f [2] 48 ba [2] 66 ba [2] 59 a6 }

  condition:
    any of them
}