rule TTP_XOR_WriteProcessMemory_b19e {
  strings:
    $key_b19e = { e6 ec [2] d4 ce [2] d2 fb [2] fc fb [2] c3 e7 }

  condition:
    any of them
}