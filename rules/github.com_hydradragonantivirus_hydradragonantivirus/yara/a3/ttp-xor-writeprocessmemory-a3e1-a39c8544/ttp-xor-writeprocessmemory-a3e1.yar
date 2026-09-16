rule TTP_XOR_WriteProcessMemory_a3e1 {
  strings:
    $key_a3e1 = { f4 93 [2] c6 b1 [2] c0 84 [2] ee 84 [2] d1 98 }

  condition:
    any of them
}