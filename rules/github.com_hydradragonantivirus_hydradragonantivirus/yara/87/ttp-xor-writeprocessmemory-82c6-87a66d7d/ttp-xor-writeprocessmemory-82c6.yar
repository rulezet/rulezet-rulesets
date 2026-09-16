rule TTP_XOR_WriteProcessMemory_82c6 {
  strings:
    $key_82c6 = { d5 b4 [2] e7 96 [2] e1 a3 [2] cf a3 [2] f0 bf }

  condition:
    any of them
}