rule TTP_XOR_WriteProcessMemory_43df {
  strings:
    $key_43df = { 14 ad [2] 26 8f [2] 20 ba [2] 0e ba [2] 31 a6 }

  condition:
    any of them
}