rule TTP_XOR_WriteProcessMemory_d4bc {
  strings:
    $key_d4bc = { 83 ce [2] b1 ec [2] b7 d9 [2] 99 d9 [2] a6 c5 }

  condition:
    any of them
}