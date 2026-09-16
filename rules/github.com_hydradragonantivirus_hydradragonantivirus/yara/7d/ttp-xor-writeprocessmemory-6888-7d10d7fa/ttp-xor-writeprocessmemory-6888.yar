rule TTP_XOR_WriteProcessMemory_6888 {
  strings:
    $key_6888 = { 3f fa [2] 0d d8 [2] 0b ed [2] 25 ed [2] 1a f1 }

  condition:
    any of them
}