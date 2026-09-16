rule TTP_XOR_WriteProcessMemory_9274 {
  strings:
    $key_9274 = { c5 06 [2] f7 24 [2] f1 11 [2] df 11 [2] e0 0d }

  condition:
    any of them
}