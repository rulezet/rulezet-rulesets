rule TTP_XOR_WriteProcessMemory_9225 {
  strings:
    $key_9225 = { c5 57 [2] f7 75 [2] f1 40 [2] df 40 [2] e0 5c }

  condition:
    any of them
}