rule TTP_XOR_WriteProcessMemory_9096 {
  strings:
    $key_9096 = { c7 e4 [2] f5 c6 [2] f3 f3 [2] dd f3 [2] e2 ef }

  condition:
    any of them
}