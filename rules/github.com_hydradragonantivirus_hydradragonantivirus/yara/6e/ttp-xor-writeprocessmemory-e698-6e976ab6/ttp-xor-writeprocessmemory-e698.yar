rule TTP_XOR_WriteProcessMemory_e698 {
  strings:
    $key_e698 = { b1 ea [2] 83 c8 [2] 85 fd [2] ab fd [2] 94 e1 }

  condition:
    any of them
}