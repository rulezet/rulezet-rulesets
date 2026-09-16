rule TTP_XOR_WriteProcessMemory_80c6 {
  strings:
    $key_80c6 = { d7 b4 [2] e5 96 [2] e3 a3 [2] cd a3 [2] f2 bf }

  condition:
    any of them
}