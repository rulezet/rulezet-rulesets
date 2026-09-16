rule TTP_XOR_WriteProcessMemory_72bc {
  strings:
    $key_72bc = { 25 ce [2] 17 ec [2] 11 d9 [2] 3f d9 [2] 00 c5 }

  condition:
    any of them
}