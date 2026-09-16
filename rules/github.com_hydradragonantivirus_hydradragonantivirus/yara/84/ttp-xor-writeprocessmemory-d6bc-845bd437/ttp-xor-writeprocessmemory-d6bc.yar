rule TTP_XOR_WriteProcessMemory_d6bc {
  strings:
    $key_d6bc = { 81 ce [2] b3 ec [2] b5 d9 [2] 9b d9 [2] a4 c5 }

  condition:
    any of them
}