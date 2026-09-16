rule TTP_XOR_WriteProcessMemory_9440 {
  strings:
    $key_9440 = { c3 32 [2] f1 10 [2] f7 25 [2] d9 25 [2] e6 39 }

  condition:
    any of them
}