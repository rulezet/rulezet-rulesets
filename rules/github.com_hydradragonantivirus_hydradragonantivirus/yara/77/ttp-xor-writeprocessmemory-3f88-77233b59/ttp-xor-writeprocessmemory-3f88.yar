rule TTP_XOR_WriteProcessMemory_3f88 {
  strings:
    $key_3f88 = { 68 fa [2] 5a d8 [2] 5c ed [2] 72 ed [2] 4d f1 }

  condition:
    any of them
}