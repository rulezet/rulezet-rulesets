rule TTP_XOR_WriteProcessMemory_c19e {
  strings:
    $key_c19e = { 96 ec [2] a4 ce [2] a2 fb [2] 8c fb [2] b3 e7 }

  condition:
    any of them
}