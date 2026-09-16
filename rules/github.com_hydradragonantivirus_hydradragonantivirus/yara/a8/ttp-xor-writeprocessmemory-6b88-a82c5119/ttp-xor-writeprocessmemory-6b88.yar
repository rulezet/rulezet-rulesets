rule TTP_XOR_WriteProcessMemory_6b88 {
  strings:
    $key_6b88 = { 3c fa [2] 0e d8 [2] 08 ed [2] 26 ed [2] 19 f1 }

  condition:
    any of them
}