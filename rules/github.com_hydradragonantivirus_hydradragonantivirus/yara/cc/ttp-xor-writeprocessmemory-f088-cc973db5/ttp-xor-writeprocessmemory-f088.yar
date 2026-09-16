rule TTP_XOR_WriteProcessMemory_f088 {
  strings:
    $key_f088 = { a7 fa [2] 95 d8 [2] 93 ed [2] bd ed [2] 82 f1 }

  condition:
    any of them
}