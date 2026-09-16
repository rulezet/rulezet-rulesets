rule TTP_XOR_WriteProcessMemory_0a88 {
  strings:
    $key_0a88 = { 5d fa [2] 6f d8 [2] 69 ed [2] 47 ed [2] 78 f1 }

  condition:
    any of them
}