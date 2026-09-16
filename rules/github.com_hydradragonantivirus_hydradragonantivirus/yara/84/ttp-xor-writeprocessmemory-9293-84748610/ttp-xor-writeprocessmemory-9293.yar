rule TTP_XOR_WriteProcessMemory_9293 {
  strings:
    $key_9293 = { c5 e1 [2] f7 c3 [2] f1 f6 [2] df f6 [2] e0 ea }

  condition:
    any of them
}