rule TTP_XOR_WriteProcessMemory_ca9e {
  strings:
    $key_ca9e = { 9d ec [2] af ce [2] a9 fb [2] 87 fb [2] b8 e7 }

  condition:
    any of them
}