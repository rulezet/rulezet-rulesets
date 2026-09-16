rule TTP_XOR_WriteProcessMemory_48bb {
  strings:
    $key_48bb = { 1f c9 [2] 2d eb [2] 2b de [2] 05 de [2] 3a c2 }

  condition:
    any of them
}