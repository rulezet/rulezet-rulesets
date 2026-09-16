rule TTP_XOR_WriteProcessMemory_3c88 {
  strings:
    $key_3c88 = { 6b fa [2] 59 d8 [2] 5f ed [2] 71 ed [2] 4e f1 }

  condition:
    any of them
}