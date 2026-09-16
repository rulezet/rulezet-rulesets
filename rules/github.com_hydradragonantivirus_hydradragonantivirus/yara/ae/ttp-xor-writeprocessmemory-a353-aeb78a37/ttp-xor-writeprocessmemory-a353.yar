rule TTP_XOR_WriteProcessMemory_a353 {
  strings:
    $key_a353 = { f4 21 [2] c6 03 [2] c0 36 [2] ee 36 [2] d1 2a }

  condition:
    any of them
}