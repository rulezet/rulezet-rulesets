rule TTP_XOR_WriteProcessMemory_9296 {
  strings:
    $key_9296 = { c5 e4 [2] f7 c6 [2] f1 f3 [2] df f3 [2] e0 ef }

  condition:
    any of them
}