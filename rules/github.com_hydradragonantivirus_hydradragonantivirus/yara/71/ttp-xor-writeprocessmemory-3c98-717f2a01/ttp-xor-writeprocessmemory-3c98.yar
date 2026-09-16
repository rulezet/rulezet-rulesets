rule TTP_XOR_WriteProcessMemory_3c98 {
  strings:
    $key_3c98 = { 6b ea [2] 59 c8 [2] 5f fd [2] 71 fd [2] 4e e1 }

  condition:
    any of them
}