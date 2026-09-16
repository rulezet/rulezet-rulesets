rule TTP_XOR_WriteProcessMemory_d29e {
  strings:
    $key_d29e = { 85 ec [2] b7 ce [2] b1 fb [2] 9f fb [2] a0 e7 }

  condition:
    any of them
}