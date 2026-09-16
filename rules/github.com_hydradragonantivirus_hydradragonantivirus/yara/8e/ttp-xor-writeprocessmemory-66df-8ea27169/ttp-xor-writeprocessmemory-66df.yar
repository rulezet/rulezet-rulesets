rule TTP_XOR_WriteProcessMemory_66df {
  strings:
    $key_66df = { 31 ad [2] 03 8f [2] 05 ba [2] 2b ba [2] 14 a6 }

  condition:
    any of them
}