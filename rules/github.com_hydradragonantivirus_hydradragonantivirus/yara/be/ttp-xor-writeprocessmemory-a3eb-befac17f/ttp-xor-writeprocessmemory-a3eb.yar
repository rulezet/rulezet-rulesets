rule TTP_XOR_WriteProcessMemory_a3eb {
  strings:
    $key_a3eb = { f4 99 [2] c6 bb [2] c0 8e [2] ee 8e [2] d1 92 }

  condition:
    any of them
}