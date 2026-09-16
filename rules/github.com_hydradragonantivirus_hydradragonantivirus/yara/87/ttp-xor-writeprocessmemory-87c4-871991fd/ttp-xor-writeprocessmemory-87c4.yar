rule TTP_XOR_WriteProcessMemory_87c4 {
  strings:
    $key_87c4 = { d0 b6 [2] e2 94 [2] e4 a1 [2] ca a1 [2] f5 bd }

  condition:
    any of them
}