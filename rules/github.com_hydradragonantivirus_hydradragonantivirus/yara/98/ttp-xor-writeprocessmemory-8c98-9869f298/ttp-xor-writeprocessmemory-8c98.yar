rule TTP_XOR_WriteProcessMemory_8c98 {
  strings:
    $key_8c98 = { db ea [2] e9 c8 [2] ef fd [2] c1 fd [2] fe e1 }

  condition:
    any of them
}