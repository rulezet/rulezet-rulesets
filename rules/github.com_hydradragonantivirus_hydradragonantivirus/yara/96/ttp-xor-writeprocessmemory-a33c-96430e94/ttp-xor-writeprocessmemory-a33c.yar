rule TTP_XOR_WriteProcessMemory_a33c {
  strings:
    $key_a33c = { f4 4e [2] c6 6c [2] c0 59 [2] ee 59 [2] d1 45 }

  condition:
    any of them
}