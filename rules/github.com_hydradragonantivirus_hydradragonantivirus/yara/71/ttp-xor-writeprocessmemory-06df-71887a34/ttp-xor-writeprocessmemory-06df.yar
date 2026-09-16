rule TTP_XOR_WriteProcessMemory_06df {
  strings:
    $key_06df = { 51 ad [2] 63 8f [2] 65 ba [2] 4b ba [2] 74 a6 }

  condition:
    any of them
}