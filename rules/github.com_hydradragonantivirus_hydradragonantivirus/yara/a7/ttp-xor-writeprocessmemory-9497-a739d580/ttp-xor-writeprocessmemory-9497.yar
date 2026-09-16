rule TTP_XOR_WriteProcessMemory_9497 {
  strings:
    $key_9497 = { c3 e5 [2] f1 c7 [2] f7 f2 [2] d9 f2 [2] e6 ee }

  condition:
    any of them
}