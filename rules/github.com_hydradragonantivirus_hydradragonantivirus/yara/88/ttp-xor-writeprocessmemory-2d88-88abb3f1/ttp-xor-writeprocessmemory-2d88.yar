rule TTP_XOR_WriteProcessMemory_2d88 {
  strings:
    $key_2d88 = { 7a fa [2] 48 d8 [2] 4e ed [2] 60 ed [2] 5f f1 }

  condition:
    any of them
}