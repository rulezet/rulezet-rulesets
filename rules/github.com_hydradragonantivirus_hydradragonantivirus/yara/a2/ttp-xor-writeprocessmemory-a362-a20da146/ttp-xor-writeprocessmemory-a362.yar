rule TTP_XOR_WriteProcessMemory_a362 {
  strings:
    $key_a362 = { f4 10 [2] c6 32 [2] c0 07 [2] ee 07 [2] d1 1b }

  condition:
    any of them
}