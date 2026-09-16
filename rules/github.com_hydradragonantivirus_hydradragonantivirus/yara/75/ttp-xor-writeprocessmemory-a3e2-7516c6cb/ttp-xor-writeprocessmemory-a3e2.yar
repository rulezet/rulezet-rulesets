rule TTP_XOR_WriteProcessMemory_a3e2 {
  strings:
    $key_a3e2 = { f4 90 [2] c6 b2 [2] c0 87 [2] ee 87 [2] d1 9b }

  condition:
    any of them
}