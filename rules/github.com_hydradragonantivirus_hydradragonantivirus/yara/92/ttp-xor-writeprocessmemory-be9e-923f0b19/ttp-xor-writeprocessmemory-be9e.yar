rule TTP_XOR_WriteProcessMemory_be9e {
  strings:
    $key_be9e = { e9 ec [2] db ce [2] dd fb [2] f3 fb [2] cc e7 }

  condition:
    any of them
}