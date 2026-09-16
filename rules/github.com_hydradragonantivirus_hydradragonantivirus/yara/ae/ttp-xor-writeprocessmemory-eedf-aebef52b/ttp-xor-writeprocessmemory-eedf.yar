rule TTP_XOR_WriteProcessMemory_eedf {
  strings:
    $key_eedf = { b9 ad [2] 8b 8f [2] 8d ba [2] a3 ba [2] 9c a6 }

  condition:
    any of them
}