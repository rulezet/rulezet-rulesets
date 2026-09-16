rule TTP_XOR_WriteProcessMemory_87c6 {
  strings:
    $key_87c6 = { d0 b4 [2] e2 96 [2] e4 a3 [2] ca a3 [2] f5 bf }

  condition:
    any of them
}