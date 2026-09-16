rule TTP_XOR_WriteProcessMemory_9188 {
  strings:
    $key_9188 = { c6 fa [2] f4 d8 [2] f2 ed [2] dc ed [2] e3 f1 }

  condition:
    any of them
}