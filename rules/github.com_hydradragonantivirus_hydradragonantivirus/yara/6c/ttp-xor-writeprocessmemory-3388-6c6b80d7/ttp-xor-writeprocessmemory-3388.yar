rule TTP_XOR_WriteProcessMemory_3388 {
  strings:
    $key_3388 = { 64 fa [2] 56 d8 [2] 50 ed [2] 7e ed [2] 41 f1 }

  condition:
    any of them
}