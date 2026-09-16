rule TTP_XOR_WriteProcessMemory_6588 {
  strings:
    $key_6588 = { 32 fa [2] 00 d8 [2] 06 ed [2] 28 ed [2] 17 f1 }

  condition:
    any of them
}