rule TTP_XOR_WriteProcessMemory_2f88 {
  strings:
    $key_2f88 = { 78 fa [2] 4a d8 [2] 4c ed [2] 62 ed [2] 5d f1 }

  condition:
    any of them
}