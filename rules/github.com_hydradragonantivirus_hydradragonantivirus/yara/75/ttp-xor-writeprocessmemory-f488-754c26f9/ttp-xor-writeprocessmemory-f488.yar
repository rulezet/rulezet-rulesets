rule TTP_XOR_WriteProcessMemory_f488 {
  strings:
    $key_f488 = { a3 fa [2] 91 d8 [2] 97 ed [2] b9 ed [2] 86 f1 }

  condition:
    any of them
}