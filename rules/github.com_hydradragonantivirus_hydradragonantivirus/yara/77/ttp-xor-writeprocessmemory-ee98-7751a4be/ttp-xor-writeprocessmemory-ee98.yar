rule TTP_XOR_WriteProcessMemory_ee98 {
  strings:
    $key_ee98 = { b9 ea [2] 8b c8 [2] 8d fd [2] a3 fd [2] 9c e1 }

  condition:
    any of them
}