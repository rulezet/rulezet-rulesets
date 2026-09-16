rule TTP_XOR_WriteProcessMemory_a348 {
  strings:
    $key_a348 = { f4 3a [2] c6 18 [2] c0 2d [2] ee 2d [2] d1 31 }

  condition:
    any of them
}