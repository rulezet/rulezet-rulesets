rule TTP_XOR_WriteProcessMemory_80d6 {
  strings:
    $key_80d6 = { d7 a4 [2] e5 86 [2] e3 b3 [2] cd b3 [2] f2 af }

  condition:
    any of them
}