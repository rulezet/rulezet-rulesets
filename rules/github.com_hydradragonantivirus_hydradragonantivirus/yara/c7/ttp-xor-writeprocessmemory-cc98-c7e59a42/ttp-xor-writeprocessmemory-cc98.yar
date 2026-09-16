rule TTP_XOR_WriteProcessMemory_cc98 {
  strings:
    $key_cc98 = { 9b ea [2] a9 c8 [2] af fd [2] 81 fd [2] be e1 }

  condition:
    any of them
}