rule TTP_XOR_WriteProcessMemory_6f88 {
  strings:
    $key_6f88 = { 38 fa [2] 0a d8 [2] 0c ed [2] 22 ed [2] 1d f1 }

  condition:
    any of them
}