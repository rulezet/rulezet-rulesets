rule TTP_XOR_WriteProcessMemory_fc88 {
  strings:
    $key_fc88 = { ab fa [2] 99 d8 [2] 9f ed [2] b1 ed [2] 8e f1 }

  condition:
    any of them
}