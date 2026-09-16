rule TTP_XOR_WriteProcessMemory_8096 {
  strings:
    $key_8096 = { d7 e4 [2] e5 c6 [2] e3 f3 [2] cd f3 [2] f2 ef }

  condition:
    any of them
}