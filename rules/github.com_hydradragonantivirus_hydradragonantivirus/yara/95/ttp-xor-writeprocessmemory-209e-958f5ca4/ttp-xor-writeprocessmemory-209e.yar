rule TTP_XOR_WriteProcessMemory_209e {
  strings:
    $key_209e = { 77 ec [2] 45 ce [2] 43 fb [2] 6d fb [2] 52 e7 }

  condition:
    any of them
}