rule TTP_XOR_WriteProcessMemory_2e98 {
  strings:
    $key_2e98 = { 79 ea [2] 4b c8 [2] 4d fd [2] 63 fd [2] 5c e1 }

  condition:
    any of them
}