rule TTP_XOR_WriteProcessMemory_9682 {
  strings:
    $key_9682 = { c1 f0 [2] f3 d2 [2] f5 e7 [2] db e7 [2] e4 fb }

  condition:
    any of them
}