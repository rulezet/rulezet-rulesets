rule TTP_XOR_WriteProcessMemory_a36b {
  strings:
    $key_a36b = { f4 19 [2] c6 3b [2] c0 0e [2] ee 0e [2] d1 12 }

  condition:
    any of them
}