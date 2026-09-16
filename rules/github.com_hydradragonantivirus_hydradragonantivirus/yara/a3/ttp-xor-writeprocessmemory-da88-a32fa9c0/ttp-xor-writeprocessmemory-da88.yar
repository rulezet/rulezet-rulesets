rule TTP_XOR_WriteProcessMemory_da88 {
  strings:
    $key_da88 = { 8d fa [2] bf d8 [2] b9 ed [2] 97 ed [2] a8 f1 }

  condition:
    any of them
}