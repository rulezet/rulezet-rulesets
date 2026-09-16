rule TTP_XOR_WriteProcessMemory_a342 {
  strings:
    $key_a342 = { f4 30 [2] c6 12 [2] c0 27 [2] ee 27 [2] d1 3b }

  condition:
    any of them
}