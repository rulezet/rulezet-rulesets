rule TTP_XOR_WriteProcessMemory_3a88 {
  strings:
    $key_3a88 = { 6d fa [2] 5f d8 [2] 59 ed [2] 77 ed [2] 48 f1 }

  condition:
    any of them
}