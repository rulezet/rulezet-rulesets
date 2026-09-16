rule TTP_XOR_WriteProcessMemory_4eac {
  strings:
    $key_4eac = { 19 de [2] 2b fc [2] 2d c9 [2] 03 c9 [2] 3c d5 }

  condition:
    any of them
}