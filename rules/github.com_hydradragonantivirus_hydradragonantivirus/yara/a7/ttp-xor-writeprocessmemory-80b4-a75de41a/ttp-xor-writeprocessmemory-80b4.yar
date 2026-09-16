rule TTP_XOR_WriteProcessMemory_80b4 {
  strings:
    $key_80b4 = { d7 c6 [2] e5 e4 [2] e3 d1 [2] cd d1 [2] f2 cd }

  condition:
    any of them
}