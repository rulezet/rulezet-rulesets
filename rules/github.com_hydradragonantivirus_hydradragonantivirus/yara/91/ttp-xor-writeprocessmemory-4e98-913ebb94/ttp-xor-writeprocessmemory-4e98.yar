rule TTP_XOR_WriteProcessMemory_4e98 {
  strings:
    $key_4e98 = { 19 ea [2] 2b c8 [2] 2d fd [2] 03 fd [2] 3c e1 }

  condition:
    any of them
}