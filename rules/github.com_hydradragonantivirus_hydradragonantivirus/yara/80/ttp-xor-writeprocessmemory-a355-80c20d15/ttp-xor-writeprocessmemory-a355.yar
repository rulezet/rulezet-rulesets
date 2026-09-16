rule TTP_XOR_WriteProcessMemory_a355 {
  strings:
    $key_a355 = { f4 27 [2] c6 05 [2] c0 30 [2] ee 30 [2] d1 2c }

  condition:
    any of them
}