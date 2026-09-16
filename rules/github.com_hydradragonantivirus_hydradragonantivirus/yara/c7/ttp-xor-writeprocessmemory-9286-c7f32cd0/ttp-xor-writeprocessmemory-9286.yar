rule TTP_XOR_WriteProcessMemory_9286 {
  strings:
    $key_9286 = { c5 f4 [2] f7 d6 [2] f1 e3 [2] df e3 [2] e0 ff }

  condition:
    any of them
}