rule TTP_XOR_WriteProcessMemory_9690 {
  strings:
    $key_9690 = { c1 e2 [2] f3 c0 [2] f5 f5 [2] db f5 [2] e4 e9 }

  condition:
    any of them
}