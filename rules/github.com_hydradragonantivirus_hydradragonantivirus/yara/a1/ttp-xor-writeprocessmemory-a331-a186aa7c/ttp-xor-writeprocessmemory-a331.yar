rule TTP_XOR_WriteProcessMemory_a331 {
  strings:
    $key_a331 = { f4 43 [2] c6 61 [2] c0 54 [2] ee 54 [2] d1 48 }

  condition:
    any of them
}