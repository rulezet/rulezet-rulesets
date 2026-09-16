rule TTP_XOR_WriteProcessMemory_1388 {
  strings:
    $key_1388 = { 44 fa [2] 76 d8 [2] 70 ed [2] 5e ed [2] 61 f1 }

  condition:
    any of them
}