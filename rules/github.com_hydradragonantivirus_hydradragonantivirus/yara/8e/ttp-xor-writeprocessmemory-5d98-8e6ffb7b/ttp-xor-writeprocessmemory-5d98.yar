rule TTP_XOR_WriteProcessMemory_5d98 {
  strings:
    $key_5d98 = { 0a ea [2] 38 c8 [2] 3e fd [2] 10 fd [2] 2f e1 }

  condition:
    any of them
}