rule TTP_XOR_WriteProcessMemory_4f9e {
  strings:
    $key_4f9e = { 18 ec [2] 2a ce [2] 2c fb [2] 02 fb [2] 3d e7 }

  condition:
    any of them
}