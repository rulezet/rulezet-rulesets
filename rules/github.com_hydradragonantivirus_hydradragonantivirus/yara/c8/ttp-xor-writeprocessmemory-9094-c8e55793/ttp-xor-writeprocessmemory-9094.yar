rule TTP_XOR_WriteProcessMemory_9094 {
  strings:
    $key_9094 = { c7 e6 [2] f5 c4 [2] f3 f1 [2] dd f1 [2] e2 ed }

  condition:
    any of them
}