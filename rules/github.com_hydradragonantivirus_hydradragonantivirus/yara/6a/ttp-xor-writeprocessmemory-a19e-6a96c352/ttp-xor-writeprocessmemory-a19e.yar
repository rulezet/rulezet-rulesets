rule TTP_XOR_WriteProcessMemory_a19e {
  strings:
    $key_a19e = { f6 ec [2] c4 ce [2] c2 fb [2] ec fb [2] d3 e7 }

  condition:
    any of them
}