rule TTP_XOR_WriteProcessMemory_a368 {
  strings:
    $key_a368 = { f4 1a [2] c6 38 [2] c0 0d [2] ee 0d [2] d1 11 }

  condition:
    any of them
}