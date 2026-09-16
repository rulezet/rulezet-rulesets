rule TTP_XOR_WriteProcessMemory_f988 {
  strings:
    $key_f988 = { ae fa [2] 9c d8 [2] 9a ed [2] b4 ed [2] 8b f1 }

  condition:
    any of them
}