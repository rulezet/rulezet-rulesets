rule TTP_XOR_WriteProcessMemory_c79e {
  strings:
    $key_c79e = { 90 ec [2] a2 ce [2] a4 fb [2] 8a fb [2] b5 e7 }

  condition:
    any of them
}