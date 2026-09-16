rule TTP_XOR_WriteProcessMemory_709e {
  strings:
    $key_709e = { 27 ec [2] 15 ce [2] 13 fb [2] 3d fb [2] 02 e7 }

  condition:
    any of them
}