rule TTP_XOR_WriteProcessMemory_9588 {
  strings:
    $key_9588 = { c2 fa [2] f0 d8 [2] f6 ed [2] d8 ed [2] e7 f1 }

  condition:
    any of them
}