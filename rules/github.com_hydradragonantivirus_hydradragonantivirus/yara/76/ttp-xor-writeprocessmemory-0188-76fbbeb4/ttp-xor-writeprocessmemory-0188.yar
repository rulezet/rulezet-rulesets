rule TTP_XOR_WriteProcessMemory_0188 {
  strings:
    $key_0188 = { 56 fa [2] 64 d8 [2] 62 ed [2] 4c ed [2] 73 f1 }

  condition:
    any of them
}