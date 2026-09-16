rule TTP_XOR_WriteProcessMemory_9244 {
  strings:
    $key_9244 = { c5 36 [2] f7 14 [2] f1 21 [2] df 21 [2] e0 3d }

  condition:
    any of them
}