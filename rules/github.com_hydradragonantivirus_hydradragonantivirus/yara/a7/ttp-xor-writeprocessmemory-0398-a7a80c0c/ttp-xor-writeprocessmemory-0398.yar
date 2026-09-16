rule TTP_XOR_WriteProcessMemory_0398 {
  strings:
    $key_0398 = { 54 ea [2] 66 c8 [2] 60 fd [2] 4e fd [2] 71 e1 }

  condition:
    any of them
}