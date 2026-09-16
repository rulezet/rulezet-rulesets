rule TTP_XOR_WriteProcessMemory_d5bc {
  strings:
    $key_d5bc = { 82 ce [2] b0 ec [2] b6 d9 [2] 98 d9 [2] a7 c5 }

  condition:
    any of them
}