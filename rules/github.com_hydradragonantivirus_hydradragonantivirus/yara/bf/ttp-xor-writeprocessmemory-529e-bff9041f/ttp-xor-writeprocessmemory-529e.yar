rule TTP_XOR_WriteProcessMemory_529e {
  strings:
    $key_529e = { 05 ec [2] 37 ce [2] 31 fb [2] 1f fb [2] 20 e7 }

  condition:
    any of them
}