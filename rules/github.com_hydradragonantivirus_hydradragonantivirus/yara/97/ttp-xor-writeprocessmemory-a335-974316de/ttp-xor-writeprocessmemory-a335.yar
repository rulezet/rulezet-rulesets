rule TTP_XOR_WriteProcessMemory_a335 {
  strings:
    $key_a335 = { f4 47 [2] c6 65 [2] c0 50 [2] ee 50 [2] d1 4c }

  condition:
    any of them
}