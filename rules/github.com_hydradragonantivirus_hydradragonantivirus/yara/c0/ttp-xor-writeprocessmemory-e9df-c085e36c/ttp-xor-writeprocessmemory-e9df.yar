rule TTP_XOR_WriteProcessMemory_e9df {
  strings:
    $key_e9df = { be ad [2] 8c 8f [2] 8a ba [2] a4 ba [2] 9b a6 }

  condition:
    any of them
}