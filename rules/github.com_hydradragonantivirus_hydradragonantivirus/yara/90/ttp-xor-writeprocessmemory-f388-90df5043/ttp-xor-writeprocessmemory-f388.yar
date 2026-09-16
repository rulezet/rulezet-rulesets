rule TTP_XOR_WriteProcessMemory_f388 {
  strings:
    $key_f388 = { a4 fa [2] 96 d8 [2] 90 ed [2] be ed [2] 81 f1 }

  condition:
    any of them
}