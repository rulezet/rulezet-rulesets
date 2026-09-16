rule TTP_XOR_WriteProcessMemory_5eac {
  strings:
    $key_5eac = { 09 de [2] 3b fc [2] 3d c9 [2] 13 c9 [2] 2c d5 }

  condition:
    any of them
}