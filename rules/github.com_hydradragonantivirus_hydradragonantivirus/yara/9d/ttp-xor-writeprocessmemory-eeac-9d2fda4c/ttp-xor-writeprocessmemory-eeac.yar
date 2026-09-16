rule TTP_XOR_WriteProcessMemory_eeac {
  strings:
    $key_eeac = { b9 de [2] 8b fc [2] 8d c9 [2] a3 c9 [2] 9c d5 }

  condition:
    any of them
}