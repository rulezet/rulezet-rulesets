rule TTP_XOR_WriteProcessMemory_a3e9 {
  strings:
    $key_a3e9 = { f4 9b [2] c6 b9 [2] c0 8c [2] ee 8c [2] d1 90 }

  condition:
    any of them
}