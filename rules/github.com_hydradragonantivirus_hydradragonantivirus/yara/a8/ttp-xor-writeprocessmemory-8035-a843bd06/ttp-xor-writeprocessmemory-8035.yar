rule TTP_XOR_WriteProcessMemory_8035 {
  strings:
    $key_8035 = { d7 47 [2] e5 65 [2] e3 50 [2] cd 50 [2] f2 4c }

  condition:
    any of them
}