rule TTP_XOR_WriteProcessMemory_f89e {
  strings:
    $key_f89e = { af ec [2] 9d ce [2] 9b fb [2] b5 fb [2] 8a e7 }

  condition:
    any of them
}