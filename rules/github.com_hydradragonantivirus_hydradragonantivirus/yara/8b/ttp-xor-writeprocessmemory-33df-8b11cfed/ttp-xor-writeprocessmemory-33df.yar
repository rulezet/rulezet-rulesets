rule TTP_XOR_WriteProcessMemory_33df {
  strings:
    $key_33df = { 64 ad [2] 56 8f [2] 50 ba [2] 7e ba [2] 41 a6 }

  condition:
    any of them
}