rule TTP_XOR_WriteProcessMemory_d498 {
  strings:
    $key_d498 = { 83 ea [2] b1 c8 [2] b7 fd [2] 99 fd [2] a6 e1 }

  condition:
    any of them
}