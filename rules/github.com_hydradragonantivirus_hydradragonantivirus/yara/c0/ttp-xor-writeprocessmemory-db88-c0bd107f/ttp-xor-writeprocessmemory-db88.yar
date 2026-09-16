rule TTP_XOR_WriteProcessMemory_db88 {
  strings:
    $key_db88 = { 8c fa [2] be d8 [2] b8 ed [2] 96 ed [2] a9 f1 }

  condition:
    any of them
}