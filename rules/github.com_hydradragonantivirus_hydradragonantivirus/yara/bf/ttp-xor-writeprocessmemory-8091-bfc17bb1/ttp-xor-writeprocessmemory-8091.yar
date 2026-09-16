rule TTP_XOR_WriteProcessMemory_8091 {
  strings:
    $key_8091 = { d7 e3 [2] e5 c1 [2] e3 f4 [2] cd f4 [2] f2 e8 }

  condition:
    any of them
}