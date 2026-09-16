rule TTP_XOR_WriteProcessMemory_9254 {
  strings:
    $key_9254 = { c5 26 [2] f7 04 [2] f1 31 [2] df 31 [2] e0 2d }

  condition:
    any of them
}