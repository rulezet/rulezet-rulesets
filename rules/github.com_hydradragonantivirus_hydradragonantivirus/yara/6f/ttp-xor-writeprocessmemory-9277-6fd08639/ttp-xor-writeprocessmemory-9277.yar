rule TTP_XOR_WriteProcessMemory_9277 {
  strings:
    $key_9277 = { c5 05 [2] f7 27 [2] f1 12 [2] df 12 [2] e0 0e }

  condition:
    any of them
}