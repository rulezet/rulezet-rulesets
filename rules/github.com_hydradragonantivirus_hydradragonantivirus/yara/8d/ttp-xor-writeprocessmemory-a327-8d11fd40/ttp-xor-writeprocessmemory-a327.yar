rule TTP_XOR_WriteProcessMemory_a327 {
  strings:
    $key_a327 = { f4 55 [2] c6 77 [2] c0 42 [2] ee 42 [2] d1 5e }

  condition:
    any of them
}