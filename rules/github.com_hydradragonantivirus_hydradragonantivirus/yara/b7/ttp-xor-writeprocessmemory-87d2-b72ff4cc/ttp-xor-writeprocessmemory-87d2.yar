rule TTP_XOR_WriteProcessMemory_87d2 {
  strings:
    $key_87d2 = { d0 a0 [2] e2 82 [2] e4 b7 [2] ca b7 [2] f5 ab }

  condition:
    any of them
}