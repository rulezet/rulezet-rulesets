rule TTP_XOR_WriteProcessMemory_6c88 {
  strings:
    $key_6c88 = { 3b fa [2] 09 d8 [2] 0f ed [2] 21 ed [2] 1e f1 }

  condition:
    any of them
}