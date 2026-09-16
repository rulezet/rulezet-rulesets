rule TTP_XOR_WriteProcessMemory_a30b {
  strings:
    $key_a30b = { f4 79 [2] c6 5b [2] c0 6e [2] ee 6e [2] d1 72 }

  condition:
    any of them
}