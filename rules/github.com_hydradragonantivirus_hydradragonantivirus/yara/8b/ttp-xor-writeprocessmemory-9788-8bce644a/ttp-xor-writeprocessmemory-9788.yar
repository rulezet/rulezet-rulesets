rule TTP_XOR_WriteProcessMemory_9788 {
  strings:
    $key_9788 = { c0 fa [2] f2 d8 [2] f4 ed [2] da ed [2] e5 f1 }

  condition:
    any of them
}