rule TTP_XOR_WriteProcessMemory_2edf {
  strings:
    $key_2edf = { 79 ad [2] 4b 8f [2] 4d ba [2] 63 ba [2] 5c a6 }

  condition:
    any of them
}