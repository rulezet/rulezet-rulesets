rule TTP_XOR_WriteProcessMemory_009e {
  strings:
    $key_009e = { 57 ec [2] 65 ce [2] 63 fb [2] 4d fb [2] 72 e7 }

  condition:
    any of them
}