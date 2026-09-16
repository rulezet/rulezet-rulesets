rule TTP_XOR_WriteProcessMemory_6eac {
  strings:
    $key_6eac = { 39 de [2] 0b fc [2] 0d c9 [2] 23 c9 [2] 1c d5 }

  condition:
    any of them
}