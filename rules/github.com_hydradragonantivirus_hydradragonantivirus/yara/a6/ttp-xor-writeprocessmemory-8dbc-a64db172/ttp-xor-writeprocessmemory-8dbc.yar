rule TTP_XOR_WriteProcessMemory_8dbc {
  strings:
    $key_8dbc = { da ce [2] e8 ec [2] ee d9 [2] c0 d9 [2] ff c5 }

  condition:
    any of them
}