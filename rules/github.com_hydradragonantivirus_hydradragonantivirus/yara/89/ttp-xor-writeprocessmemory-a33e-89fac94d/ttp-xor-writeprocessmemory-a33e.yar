rule TTP_XOR_WriteProcessMemory_a33e {
  strings:
    $key_a33e = { f4 4c [2] c6 6e [2] c0 5b [2] ee 5b [2] d1 47 }

  condition:
    any of them
}