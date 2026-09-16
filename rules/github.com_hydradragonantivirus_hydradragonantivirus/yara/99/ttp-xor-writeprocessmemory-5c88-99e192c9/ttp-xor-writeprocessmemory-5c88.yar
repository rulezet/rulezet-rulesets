rule TTP_XOR_WriteProcessMemory_5c88 {
  strings:
    $key_5c88 = { 0b fa [2] 39 d8 [2] 3f ed [2] 11 ed [2] 2e f1 }

  condition:
    any of them
}