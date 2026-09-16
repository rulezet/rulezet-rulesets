rule TTP_XOR_WriteProcessMemory_269e {
  strings:
    $key_269e = { 71 ec [2] 43 ce [2] 45 fb [2] 6b fb [2] 54 e7 }

  condition:
    any of them
}