rule TTP_XOR_WriteProcessMemory_a370 {
  strings:
    $key_a370 = { f4 02 [2] c6 20 [2] c0 15 [2] ee 15 [2] d1 09 }

  condition:
    any of them
}