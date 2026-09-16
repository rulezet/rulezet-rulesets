rule TTP_XOR_WriteProcessMemory_a39e {
  strings:
    $key_a39e = { f4 ec [2] c6 ce [2] c0 fb [2] ee fb [2] d1 e7 }

  condition:
    any of them
}