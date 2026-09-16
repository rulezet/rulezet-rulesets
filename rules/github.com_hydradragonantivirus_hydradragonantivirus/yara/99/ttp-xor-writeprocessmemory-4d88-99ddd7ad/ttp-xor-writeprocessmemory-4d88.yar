rule TTP_XOR_WriteProcessMemory_4d88 {
  strings:
    $key_4d88 = { 1a fa [2] 28 d8 [2] 2e ed [2] 00 ed [2] 3f f1 }

  condition:
    any of them
}