rule TTP_XOR_WriteProcessMemory_9693 {
  strings:
    $key_9693 = { c1 e1 [2] f3 c3 [2] f5 f6 [2] db f6 [2] e4 ea }

  condition:
    any of them
}