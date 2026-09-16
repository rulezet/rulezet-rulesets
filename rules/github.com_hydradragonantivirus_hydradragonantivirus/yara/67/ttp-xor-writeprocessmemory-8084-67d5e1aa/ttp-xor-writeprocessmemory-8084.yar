rule TTP_XOR_WriteProcessMemory_8084 {
  strings:
    $key_8084 = { d7 f6 [2] e5 d4 [2] e3 e1 [2] cd e1 [2] f2 fd }

  condition:
    any of them
}