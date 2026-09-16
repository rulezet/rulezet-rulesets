rule TTP_XOR_WriteProcessMemory_8388 {
  strings:
    $key_8388 = { d4 fa [2] e6 d8 [2] e0 ed [2] ce ed [2] f1 f1 }

  condition:
    any of them
}