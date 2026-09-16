rule TTP_XOR_WriteProcessMemory_c4bc {
  strings:
    $key_c4bc = { 93 ce [2] a1 ec [2] a7 d9 [2] 89 d9 [2] b6 c5 }

  condition:
    any of them
}