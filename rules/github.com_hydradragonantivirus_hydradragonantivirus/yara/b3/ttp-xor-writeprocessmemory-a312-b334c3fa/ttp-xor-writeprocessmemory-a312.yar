rule TTP_XOR_WriteProcessMemory_a312 {
  strings:
    $key_a312 = { f4 60 [2] c6 42 [2] c0 77 [2] ee 77 [2] d1 6b }

  condition:
    any of them
}