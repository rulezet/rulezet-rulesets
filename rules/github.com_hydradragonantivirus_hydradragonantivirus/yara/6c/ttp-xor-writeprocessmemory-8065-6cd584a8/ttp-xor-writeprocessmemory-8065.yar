rule TTP_XOR_WriteProcessMemory_8065 {
  strings:
    $key_8065 = { d7 17 [2] e5 35 [2] e3 00 [2] cd 00 [2] f2 1c }

  condition:
    any of them
}