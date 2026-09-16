rule TTP_XOR_WriteProcessMemory_1088 {
  strings:
    $key_1088 = { 47 fa [2] 75 d8 [2] 73 ed [2] 5d ed [2] 62 f1 }

  condition:
    any of them
}