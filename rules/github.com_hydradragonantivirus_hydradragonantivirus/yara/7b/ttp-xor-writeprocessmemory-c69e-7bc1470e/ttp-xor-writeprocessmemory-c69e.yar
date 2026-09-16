rule TTP_XOR_WriteProcessMemory_c69e {
  strings:
    $key_c69e = { 91 ec [2] a3 ce [2] a5 fb [2] 8b fb [2] b4 e7 }

  condition:
    any of them
}