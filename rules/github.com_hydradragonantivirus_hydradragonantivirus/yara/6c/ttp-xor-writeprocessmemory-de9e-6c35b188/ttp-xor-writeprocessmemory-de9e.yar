rule TTP_XOR_WriteProcessMemory_de9e {
  strings:
    $key_de9e = { 89 ec [2] bb ce [2] bd fb [2] 93 fb [2] ac e7 }

  condition:
    any of them
}