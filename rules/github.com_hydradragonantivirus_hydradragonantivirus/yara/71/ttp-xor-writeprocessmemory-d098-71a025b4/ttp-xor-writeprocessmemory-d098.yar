rule TTP_XOR_WriteProcessMemory_d098 {
  strings:
    $key_d098 = { 87 ea [2] b5 c8 [2] b3 fd [2] 9d fd [2] a2 e1 }

  condition:
    any of them
}