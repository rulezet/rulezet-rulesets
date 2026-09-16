rule TTP_XOR_WriteProcessMemory_c588 {
  strings:
    $key_c588 = { 92 fa [2] a0 d8 [2] a6 ed [2] 88 ed [2] b7 f1 }

  condition:
    any of them
}