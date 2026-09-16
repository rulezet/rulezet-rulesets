rule TTP_XOR_WriteProcessMemory_9694 {
  strings:
    $key_9694 = { c1 e6 [2] f3 c4 [2] f5 f1 [2] db f1 [2] e4 ed }

  condition:
    any of them
}