rule TTP_XOR_WriteProcessMemory_3b88 {
  strings:
    $key_3b88 = { 6c fa [2] 5e d8 [2] 58 ed [2] 76 ed [2] 49 f1 }

  condition:
    any of them
}