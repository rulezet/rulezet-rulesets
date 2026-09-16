rule TTP_XOR_WriteProcessMemory_58bb {
  strings:
    $key_58bb = { 0f c9 [2] 3d eb [2] 3b de [2] 15 de [2] 2a c2 }

  condition:
    any of them
}