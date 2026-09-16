rule TTP_XOR_WriteProcessMemory_d388 {
  strings:
    $key_d388 = { 84 fa [2] b6 d8 [2] b0 ed [2] 9e ed [2] a1 f1 }

  condition:
    any of them
}