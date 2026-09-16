rule TTP_XOR_WriteProcessMemory_c6bc {
  strings:
    $key_c6bc = { 91 ce [2] a3 ec [2] a5 d9 [2] 8b d9 [2] b4 c5 }

  condition:
    any of them
}