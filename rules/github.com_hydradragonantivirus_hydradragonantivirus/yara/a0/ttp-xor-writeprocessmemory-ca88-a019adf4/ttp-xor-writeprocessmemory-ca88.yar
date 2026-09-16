rule TTP_XOR_WriteProcessMemory_ca88 {
  strings:
    $key_ca88 = { 9d fa [2] af d8 [2] a9 ed [2] 87 ed [2] b8 f1 }

  condition:
    any of them
}