rule TTP_XOR_WriteProcessMemory_6d88 {
  strings:
    $key_6d88 = { 3a fa [2] 08 d8 [2] 0e ed [2] 20 ed [2] 1f f1 }

  condition:
    any of them
}