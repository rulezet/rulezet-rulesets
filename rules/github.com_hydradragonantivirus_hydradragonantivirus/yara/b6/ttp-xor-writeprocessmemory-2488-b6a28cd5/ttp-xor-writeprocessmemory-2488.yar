rule TTP_XOR_WriteProcessMemory_2488 {
  strings:
    $key_2488 = { 73 fa [2] 41 d8 [2] 47 ed [2] 69 ed [2] 56 f1 }

  condition:
    any of them
}