rule TTP_XOR_WriteProcessMemory_7e98 {
  strings:
    $key_7e98 = { 29 ea [2] 1b c8 [2] 1d fd [2] 33 fd [2] 0c e1 }

  condition:
    any of them
}