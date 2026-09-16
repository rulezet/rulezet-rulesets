rule TTP_XOR_WriteProcessMemory_9488 {
  strings:
    $key_9488 = { c3 fa [2] f1 d8 [2] f7 ed [2] d9 ed [2] e6 f1 }

  condition:
    any of them
}