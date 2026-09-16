rule TTP_XOR_WriteProcessMemory_9234 {
  strings:
    $key_9234 = { c5 46 [2] f7 64 [2] f1 51 [2] df 51 [2] e0 4d }

  condition:
    any of them
}