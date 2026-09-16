rule TTP_XOR_WriteProcessMemory_8015 {
  strings:
    $key_8015 = { d7 67 [2] e5 45 [2] e3 70 [2] cd 70 [2] f2 6c }

  condition:
    any of them
}