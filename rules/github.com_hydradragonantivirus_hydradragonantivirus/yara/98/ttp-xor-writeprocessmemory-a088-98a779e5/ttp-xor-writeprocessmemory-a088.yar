rule TTP_XOR_WriteProcessMemory_a088 {
  strings:
    $key_a088 = { f7 fa [2] c5 d8 [2] c3 ed [2] ed ed [2] d2 f1 }

  condition:
    any of them
}