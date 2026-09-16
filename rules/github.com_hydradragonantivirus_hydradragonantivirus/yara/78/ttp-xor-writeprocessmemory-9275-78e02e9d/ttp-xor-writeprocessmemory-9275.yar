rule TTP_XOR_WriteProcessMemory_9275 {
  strings:
    $key_9275 = { c5 07 [2] f7 25 [2] f1 10 [2] df 10 [2] e0 0c }

  condition:
    any of them
}