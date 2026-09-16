rule TTP_XOR_WriteProcessMemory_cd88 {
  strings:
    $key_cd88 = { 9a fa [2] a8 d8 [2] ae ed [2] 80 ed [2] bf f1 }

  condition:
    any of them
}