rule TTP_XOR_WriteProcessMemory_e788 {
  strings:
    $key_e788 = { b0 fa [2] 82 d8 [2] 84 ed [2] aa ed [2] 95 f1 }

  condition:
    any of them
}