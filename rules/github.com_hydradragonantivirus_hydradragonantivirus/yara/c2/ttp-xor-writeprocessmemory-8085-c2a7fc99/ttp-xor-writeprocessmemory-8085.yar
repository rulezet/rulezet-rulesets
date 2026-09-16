rule TTP_XOR_WriteProcessMemory_8085 {
  strings:
    $key_8085 = { d7 f7 [2] e5 d5 [2] e3 e0 [2] cd e0 [2] f2 fc }

  condition:
    any of them
}