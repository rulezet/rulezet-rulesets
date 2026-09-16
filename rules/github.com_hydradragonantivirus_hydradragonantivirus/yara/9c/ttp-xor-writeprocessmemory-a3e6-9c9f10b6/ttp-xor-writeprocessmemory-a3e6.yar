rule TTP_XOR_WriteProcessMemory_a3e6 {
  strings:
    $key_a3e6 = { f4 94 [2] c6 b6 [2] c0 83 [2] ee 83 [2] d1 9f }

  condition:
    any of them
}