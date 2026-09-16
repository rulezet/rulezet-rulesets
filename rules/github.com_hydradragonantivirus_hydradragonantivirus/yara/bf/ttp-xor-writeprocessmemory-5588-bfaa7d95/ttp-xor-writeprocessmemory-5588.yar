rule TTP_XOR_WriteProcessMemory_5588 {
  strings:
    $key_5588 = { 02 fa [2] 30 d8 [2] 36 ed [2] 18 ed [2] 27 f1 }

  condition:
    any of them
}