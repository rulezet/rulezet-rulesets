rule TTP_XOR_WriteProcessMemory_a998 {
  strings:
    $key_a998 = { fe ea [2] cc c8 [2] ca fd [2] e4 fd [2] db e1 }

  condition:
    any of them
}