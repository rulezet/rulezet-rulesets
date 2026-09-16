rule TTP_XOR_WriteProcessMemory_9217 {
  strings:
    $key_9217 = { c5 65 [2] f7 47 [2] f1 72 [2] df 72 [2] e0 6e }

  condition:
    any of them
}