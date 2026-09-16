rule TTP_XOR_WriteProcessMemory_1f88 {
  strings:
    $key_1f88 = { 48 fa [2] 7a d8 [2] 7c ed [2] 52 ed [2] 6d f1 }

  condition:
    any of them
}