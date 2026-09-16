rule TTP_XOR_WriteProcessMemory_629e {
  strings:
    $key_629e = { 35 ec [2] 07 ce [2] 01 fb [2] 2f fb [2] 10 e7 }

  condition:
    any of them
}