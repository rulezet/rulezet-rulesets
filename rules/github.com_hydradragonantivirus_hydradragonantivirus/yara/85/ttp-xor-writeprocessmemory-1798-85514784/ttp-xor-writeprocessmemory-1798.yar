rule TTP_XOR_WriteProcessMemory_1798 {
  strings:
    $key_1798 = { 40 ea [2] 72 c8 [2] 74 fd [2] 5a fd [2] 65 e1 }

  condition:
    any of them
}