rule TTP_XOR_WriteProcessMemory_a361 {
  strings:
    $key_a361 = { f4 13 [2] c6 31 [2] c0 04 [2] ee 04 [2] d1 18 }

  condition:
    any of them
}