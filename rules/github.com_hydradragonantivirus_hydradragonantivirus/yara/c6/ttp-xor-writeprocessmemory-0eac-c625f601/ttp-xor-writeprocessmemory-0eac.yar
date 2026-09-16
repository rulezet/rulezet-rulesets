rule TTP_XOR_WriteProcessMemory_0eac {
  strings:
    $key_0eac = { 59 de [2] 6b fc [2] 6d c9 [2] 43 c9 [2] 7c d5 }

  condition:
    any of them
}