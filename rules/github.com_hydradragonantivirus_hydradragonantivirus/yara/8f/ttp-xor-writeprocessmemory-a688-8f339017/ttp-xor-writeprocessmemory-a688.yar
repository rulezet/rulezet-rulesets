rule TTP_XOR_WriteProcessMemory_a688 {
  strings:
    $key_a688 = { f1 fa [2] c3 d8 [2] c5 ed [2] eb ed [2] d4 f1 }

  condition:
    any of them
}