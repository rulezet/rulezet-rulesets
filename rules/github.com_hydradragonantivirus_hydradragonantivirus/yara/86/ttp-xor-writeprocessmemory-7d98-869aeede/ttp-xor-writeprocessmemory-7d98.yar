rule TTP_XOR_WriteProcessMemory_7d98 {
  strings:
    $key_7d98 = { 2a ea [2] 18 c8 [2] 1e fd [2] 30 fd [2] 0f e1 }

  condition:
    any of them
}