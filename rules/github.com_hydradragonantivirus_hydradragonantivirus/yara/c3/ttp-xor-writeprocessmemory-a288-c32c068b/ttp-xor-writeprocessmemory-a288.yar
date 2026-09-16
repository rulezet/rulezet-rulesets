rule TTP_XOR_WriteProcessMemory_a288 {
  strings:
    $key_a288 = { f5 fa [2] c7 d8 [2] c1 ed [2] ef ed [2] d0 f1 }

  condition:
    any of them
}