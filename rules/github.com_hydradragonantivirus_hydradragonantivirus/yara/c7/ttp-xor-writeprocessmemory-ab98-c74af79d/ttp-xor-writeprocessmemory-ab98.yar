rule TTP_XOR_WriteProcessMemory_ab98 {
  strings:
    $key_ab98 = { fc ea [2] ce c8 [2] c8 fd [2] e6 fd [2] d9 e1 }

  condition:
    any of them
}