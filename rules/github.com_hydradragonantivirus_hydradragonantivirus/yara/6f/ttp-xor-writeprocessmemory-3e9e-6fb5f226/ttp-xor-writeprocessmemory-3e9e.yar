rule TTP_XOR_WriteProcessMemory_3e9e {
  strings:
    $key_3e9e = { 69 ec [2] 5b ce [2] 5d fb [2] 73 fb [2] 4c e7 }

  condition:
    any of them
}