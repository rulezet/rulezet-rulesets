rule TTP_XOR_WriteProcessMemory_a37c {
  strings:
    $key_a37c = { f4 0e [2] c6 2c [2] c0 19 [2] ee 19 [2] d1 05 }

  condition:
    any of them
}