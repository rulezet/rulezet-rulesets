rule TTP_XOR_WriteProcessMemory_9284 {
  strings:
    $key_9284 = { c5 f6 [2] f7 d4 [2] f1 e1 [2] df e1 [2] e0 fd }

  condition:
    any of them
}