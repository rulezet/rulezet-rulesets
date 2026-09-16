rule TTP_XOR_WriteProcessMemory_c088 {
  strings:
    $key_c088 = { 97 fa [2] a5 d8 [2] a3 ed [2] 8d ed [2] b2 f1 }

  condition:
    any of them
}