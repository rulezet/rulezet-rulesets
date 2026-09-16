rule TTP_XOR_WriteProcessMemory_80f5 {
  strings:
    $key_80f5 = { d7 87 [2] e5 a5 [2] e3 90 [2] cd 90 [2] f2 8c }

  condition:
    any of them
}