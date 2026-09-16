rule TTP_XOR_WriteProcessMemory_4298 {
  strings:
    $key_4298 = { 15 ea [2] 27 c8 [2] 21 fd [2] 0f fd [2] 30 e1 }

  condition:
    any of them
}