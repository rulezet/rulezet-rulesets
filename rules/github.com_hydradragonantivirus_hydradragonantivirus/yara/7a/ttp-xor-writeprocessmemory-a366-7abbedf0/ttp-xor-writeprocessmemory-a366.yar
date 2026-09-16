rule TTP_XOR_WriteProcessMemory_a366 {
  strings:
    $key_a366 = { f4 14 [2] c6 36 [2] c0 03 [2] ee 03 [2] d1 1f }

  condition:
    any of them
}