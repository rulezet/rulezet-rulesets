rule TTP_XOR_WriteProcessMemory_2c88 {
  strings:
    $key_2c88 = { 7b fa [2] 49 d8 [2] 4f ed [2] 61 ed [2] 5e f1 }

  condition:
    any of them
}