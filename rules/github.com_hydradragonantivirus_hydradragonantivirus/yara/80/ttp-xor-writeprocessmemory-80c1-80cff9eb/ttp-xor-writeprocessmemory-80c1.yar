rule TTP_XOR_WriteProcessMemory_80c1 {
  strings:
    $key_80c1 = { d7 b3 [2] e5 91 [2] e3 a4 [2] cd a4 [2] f2 b8 }

  condition:
    any of them
}