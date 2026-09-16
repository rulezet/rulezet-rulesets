rule TTP_XOR_WriteProcessMemory_9322 {
  strings:
    $key_9322 = { c4 50 [2] f6 72 [2] f0 47 [2] de 47 [2] e1 5b }

  condition:
    any of them
}