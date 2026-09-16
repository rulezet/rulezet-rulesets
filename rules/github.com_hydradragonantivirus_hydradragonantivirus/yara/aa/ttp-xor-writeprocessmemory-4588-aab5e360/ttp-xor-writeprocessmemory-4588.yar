rule TTP_XOR_WriteProcessMemory_4588 {
  strings:
    $key_4588 = { 12 fa [2] 20 d8 [2] 26 ed [2] 08 ed [2] 37 f1 }

  condition:
    any of them
}