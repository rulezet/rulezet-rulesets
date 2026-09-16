rule TTP_XOR_WriteProcessMemory_80c4 {
  strings:
    $key_80c4 = { d7 b6 [2] e5 94 [2] e3 a1 [2] cd a1 [2] f2 bd }

  condition:
    any of them
}