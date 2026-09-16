rule TTP_XOR_WriteProcessMemory_8e98 {
  strings:
    $key_8e98 = { d9 ea [2] eb c8 [2] ed fd [2] c3 fd [2] fc e1 }

  condition:
    any of them
}