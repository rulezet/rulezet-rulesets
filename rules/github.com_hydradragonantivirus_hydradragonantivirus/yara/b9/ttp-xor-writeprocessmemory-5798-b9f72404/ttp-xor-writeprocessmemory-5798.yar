rule TTP_XOR_WriteProcessMemory_5798 {
  strings:
    $key_5798 = { 00 ea [2] 32 c8 [2] 34 fd [2] 1a fd [2] 25 e1 }

  condition:
    any of them
}