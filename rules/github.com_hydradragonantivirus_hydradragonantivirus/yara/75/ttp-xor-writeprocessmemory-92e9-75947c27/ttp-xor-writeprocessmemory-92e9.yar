rule TTP_XOR_WriteProcessMemory_92e9 {
  strings:
    $key_92e9 = { c5 9b [2] f7 b9 [2] f1 8c [2] df 8c [2] e0 90 }

  condition:
    any of them
}