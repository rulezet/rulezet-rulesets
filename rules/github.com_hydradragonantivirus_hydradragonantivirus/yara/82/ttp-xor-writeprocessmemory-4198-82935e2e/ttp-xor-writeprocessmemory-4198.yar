rule TTP_XOR_WriteProcessMemory_4198 {
  strings:
    $key_4198 = { 16 ea [2] 24 c8 [2] 22 fd [2] 0c fd [2] 33 e1 }

  condition:
    any of them
}