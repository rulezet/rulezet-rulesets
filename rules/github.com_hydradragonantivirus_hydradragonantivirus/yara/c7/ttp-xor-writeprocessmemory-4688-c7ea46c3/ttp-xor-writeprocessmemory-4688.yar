rule TTP_XOR_WriteProcessMemory_4688 {
  strings:
    $key_4688 = { 11 fa [2] 23 d8 [2] 25 ed [2] 0b ed [2] 34 f1 }

  condition:
    any of them
}