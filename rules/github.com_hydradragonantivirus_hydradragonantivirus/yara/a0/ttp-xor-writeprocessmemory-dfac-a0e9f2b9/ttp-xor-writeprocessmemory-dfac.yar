rule TTP_XOR_WriteProcessMemory_dfac {
  strings:
    $key_dfac = { 88 de [2] ba fc [2] bc c9 [2] 92 c9 [2] ad d5 }

  condition:
    any of them
}