rule TTP_XOR_WriteProcessMemory_9098 {
  strings:
    $key_9098 = { c7 ea [2] f5 c8 [2] f3 fd [2] dd fd [2] e2 e1 }

  condition:
    any of them
}