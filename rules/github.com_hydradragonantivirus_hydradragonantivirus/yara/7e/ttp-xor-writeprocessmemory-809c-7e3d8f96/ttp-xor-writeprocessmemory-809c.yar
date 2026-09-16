rule TTP_XOR_WriteProcessMemory_809c {
  strings:
    $key_809c = { d7 ee [2] e5 cc [2] e3 f9 [2] cd f9 [2] f2 e5 }

  condition:
    any of them
}