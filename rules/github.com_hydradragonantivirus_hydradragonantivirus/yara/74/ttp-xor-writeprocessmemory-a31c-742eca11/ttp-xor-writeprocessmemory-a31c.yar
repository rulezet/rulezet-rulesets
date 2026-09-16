rule TTP_XOR_WriteProcessMemory_a31c {
  strings:
    $key_a31c = { f4 6e [2] c6 4c [2] c0 79 [2] ee 79 [2] d1 65 }

  condition:
    any of them
}