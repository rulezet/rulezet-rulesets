rule TTP_XOR_WriteProcessMemory_84c6 {
  strings:
    $key_84c6 = { d3 b4 [2] e1 96 [2] e7 a3 [2] c9 a3 [2] f6 bf }

  condition:
    any of them
}