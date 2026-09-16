rule TTP_XOR_WriteProcessMemory_31df {
  strings:
    $key_31df = { 66 ad [2] 54 8f [2] 52 ba [2] 7c ba [2] 43 a6 }

  condition:
    any of them
}