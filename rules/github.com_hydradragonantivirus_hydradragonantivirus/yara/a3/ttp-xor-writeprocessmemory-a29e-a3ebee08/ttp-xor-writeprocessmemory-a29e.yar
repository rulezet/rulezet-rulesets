rule TTP_XOR_WriteProcessMemory_a29e {
  strings:
    $key_a29e = { f5 ec [2] c7 ce [2] c1 fb [2] ef fb [2] d0 e7 }

  condition:
    any of them
}