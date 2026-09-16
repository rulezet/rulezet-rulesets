rule TTP_XOR_WriteProcessMemory_922b {
  strings:
    $key_922b = { c5 59 [2] f7 7b [2] f1 4e [2] df 4e [2] e0 52 }

  condition:
    any of them
}