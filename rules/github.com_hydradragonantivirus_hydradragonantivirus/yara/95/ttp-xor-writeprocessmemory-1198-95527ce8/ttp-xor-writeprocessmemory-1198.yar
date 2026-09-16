rule TTP_XOR_WriteProcessMemory_1198 {
  strings:
    $key_1198 = { 46 ea [2] 74 c8 [2] 72 fd [2] 5c fd [2] 63 e1 }

  condition:
    any of them
}