rule TTP_XOR_WriteProcessMemory_9230 {
  strings:
    $key_9230 = { c5 42 [2] f7 60 [2] f1 55 [2] df 55 [2] e0 49 }

  condition:
    any of them
}