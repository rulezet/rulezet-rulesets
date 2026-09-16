rule TTP_XOR_WriteProcessMemory_2788 {
  strings:
    $key_2788 = { 70 fa [2] 42 d8 [2] 44 ed [2] 6a ed [2] 55 f1 }

  condition:
    any of them
}