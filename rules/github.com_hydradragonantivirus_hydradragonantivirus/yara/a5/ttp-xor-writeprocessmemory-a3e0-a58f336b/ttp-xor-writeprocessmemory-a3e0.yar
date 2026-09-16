rule TTP_XOR_WriteProcessMemory_a3e0 {
  strings:
    $key_a3e0 = { f4 92 [2] c6 b0 [2] c0 85 [2] ee 85 [2] d1 99 }

  condition:
    any of them
}