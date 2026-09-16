rule TTP_XOR_WriteProcessMemory_8088 {
  strings:
    $key_8088 = { d7 fa [2] e5 d8 [2] e3 ed [2] cd ed [2] f2 f1 }

  condition:
    any of them
}