rule TTP_XOR_WriteProcessMemory_9288 {
  strings:
    $key_9288 = { c5 fa [2] f7 d8 [2] f1 ed [2] df ed [2] e0 f1 }

  condition:
    any of them
}