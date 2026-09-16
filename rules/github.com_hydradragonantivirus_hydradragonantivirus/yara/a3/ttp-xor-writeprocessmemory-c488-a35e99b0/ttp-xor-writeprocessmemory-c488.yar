rule TTP_XOR_WriteProcessMemory_c488 {
  strings:
    $key_c488 = { 93 fa [2] a1 d8 [2] a7 ed [2] 89 ed [2] b6 f1 }

  condition:
    any of them
}