rule TTP_XOR_WriteProcessMemory_6288 {
  strings:
    $key_6288 = { 35 fa [2] 07 d8 [2] 01 ed [2] 2f ed [2] 10 f1 }

  condition:
    any of them
}