rule TTP_XOR_WriteProcessMemory_a310 {
  strings:
    $key_a310 = { f4 62 [2] c6 40 [2] c0 75 [2] ee 75 [2] d1 69 }

  condition:
    any of them
}