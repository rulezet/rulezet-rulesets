rule TTP_XOR_WriteProcessMemory_9211 {
  strings:
    $key_9211 = { c5 63 [2] f7 41 [2] f1 74 [2] df 74 [2] e0 68 }

  condition:
    any of them
}