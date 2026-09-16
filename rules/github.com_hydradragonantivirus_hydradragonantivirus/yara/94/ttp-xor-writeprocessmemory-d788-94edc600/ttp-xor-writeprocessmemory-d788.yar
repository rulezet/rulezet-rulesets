rule TTP_XOR_WriteProcessMemory_d788 {
  strings:
    $key_d788 = { 80 fa [2] b2 d8 [2] b4 ed [2] 9a ed [2] a5 f1 }

  condition:
    any of them
}