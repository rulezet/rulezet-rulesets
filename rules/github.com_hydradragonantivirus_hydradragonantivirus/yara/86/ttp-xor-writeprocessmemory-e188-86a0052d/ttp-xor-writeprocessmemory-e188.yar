rule TTP_XOR_WriteProcessMemory_e188 {
  strings:
    $key_e188 = { b6 fa [2] 84 d8 [2] 82 ed [2] ac ed [2] 93 f1 }

  condition:
    any of them
}