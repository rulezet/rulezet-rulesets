rule TTP_XOR_WriteProcessMemory_f788 {
  strings:
    $key_f788 = { a0 fa [2] 92 d8 [2] 94 ed [2] ba ed [2] 85 f1 }

  condition:
    any of them
}