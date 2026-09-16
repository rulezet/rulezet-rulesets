rule TTP_XOR_WriteProcessMemory_6d98 {
  strings:
    $key_6d98 = { 3a ea [2] 08 c8 [2] 0e fd [2] 20 fd [2] 1f e1 }

  condition:
    any of them
}