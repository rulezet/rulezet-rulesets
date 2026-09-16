rule TTP_XOR_WriteProcessMemory_1c88 {
  strings:
    $key_1c88 = { 4b fa [2] 79 d8 [2] 7f ed [2] 51 ed [2] 6e f1 }

  condition:
    any of them
}