rule TTP_XOR_WriteProcessMemory_db92 {
  strings:
    $key_db92 = { 8c e0 [2] be c2 [2] b8 f7 [2] 96 f7 [2] a9 eb }

  condition:
    any of them
}