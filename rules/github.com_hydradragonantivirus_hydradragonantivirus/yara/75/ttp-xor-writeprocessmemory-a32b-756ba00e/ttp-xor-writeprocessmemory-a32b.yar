rule TTP_XOR_WriteProcessMemory_a32b {
  strings:
    $key_a32b = { f4 59 [2] c6 7b [2] c0 4e [2] ee 4e [2] d1 52 }

  condition:
    any of them
}