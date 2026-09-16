rule TTP_XOR_WriteProcessMemory_0c88 {
  strings:
    $key_0c88 = { 5b fa [2] 69 d8 [2] 6f ed [2] 41 ed [2] 7e f1 }

  condition:
    any of them
}