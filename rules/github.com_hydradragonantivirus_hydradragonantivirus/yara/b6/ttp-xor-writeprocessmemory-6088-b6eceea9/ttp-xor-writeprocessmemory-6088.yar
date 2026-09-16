rule TTP_XOR_WriteProcessMemory_6088 {
  strings:
    $key_6088 = { 37 fa [2] 05 d8 [2] 03 ed [2] 2d ed [2] 12 f1 }

  condition:
    any of them
}