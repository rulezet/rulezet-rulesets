rule TTP_XOR_WriteProcessMemory_2b88 {
  strings:
    $key_2b88 = { 7c fa [2] 4e d8 [2] 48 ed [2] 66 ed [2] 59 f1 }

  condition:
    any of them
}