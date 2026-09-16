rule TTP_XOR_WriteProcessMemory_2498 {
  strings:
    $key_2498 = { 73 ea [2] 41 c8 [2] 47 fd [2] 69 fd [2] 56 e1 }

  condition:
    any of them
}