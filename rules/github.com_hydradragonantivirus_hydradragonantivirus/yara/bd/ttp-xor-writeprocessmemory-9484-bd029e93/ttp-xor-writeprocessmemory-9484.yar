rule TTP_XOR_WriteProcessMemory_9484 {
  strings:
    $key_9484 = { c3 f6 [2] f1 d4 [2] f7 e1 [2] d9 e1 [2] e6 fd }

  condition:
    any of them
}