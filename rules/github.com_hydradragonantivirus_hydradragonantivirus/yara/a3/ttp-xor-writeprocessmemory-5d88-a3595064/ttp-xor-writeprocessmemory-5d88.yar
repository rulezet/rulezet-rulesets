rule TTP_XOR_WriteProcessMemory_5d88 {
  strings:
    $key_5d88 = { 0a fa [2] 38 d8 [2] 3e ed [2] 10 ed [2] 2f f1 }

  condition:
    any of them
}