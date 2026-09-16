rule TTP_XOR_WriteProcessMemory_8092 {
  strings:
    $key_8092 = { d7 e0 [2] e5 c2 [2] e3 f7 [2] cd f7 [2] f2 eb }

  condition:
    any of them
}