rule TTP_XOR_WriteProcessMemory_4f88 {
  strings:
    $key_4f88 = { 18 fa [2] 2a d8 [2] 2c ed [2] 02 ed [2] 3d f1 }

  condition:
    any of them
}