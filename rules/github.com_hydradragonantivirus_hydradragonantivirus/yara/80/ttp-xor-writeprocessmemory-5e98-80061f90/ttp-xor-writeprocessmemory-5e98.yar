rule TTP_XOR_WriteProcessMemory_5e98 {
  strings:
    $key_5e98 = { 09 ea [2] 3b c8 [2] 3d fd [2] 13 fd [2] 2c e1 }

  condition:
    any of them
}