rule TTP_XOR_WriteProcessMemory_52df {
  strings:
    $key_52df = { 05 ad [2] 37 8f [2] 31 ba [2] 1f ba [2] 20 a6 }

  condition:
    any of them
}