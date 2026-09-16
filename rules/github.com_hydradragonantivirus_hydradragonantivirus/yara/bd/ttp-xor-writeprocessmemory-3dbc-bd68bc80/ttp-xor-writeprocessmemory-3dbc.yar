rule TTP_XOR_WriteProcessMemory_3dbc {
  strings:
    $key_3dbc = { 6a ce [2] 58 ec [2] 5e d9 [2] 70 d9 [2] 4f c5 }

  condition:
    any of them
}