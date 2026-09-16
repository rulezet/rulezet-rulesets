rule TTP_XOR_WriteProcessMemory_85c6 {
  strings:
    $key_85c6 = { d2 b4 [2] e0 96 [2] e6 a3 [2] c8 a3 [2] f7 bf }

  condition:
    any of them
}