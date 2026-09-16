rule TTP_XOR_WriteProcessMemory_4488 {
  strings:
    $key_4488 = { 13 fa [2] 21 d8 [2] 27 ed [2] 09 ed [2] 36 f1 }

  condition:
    any of them
}