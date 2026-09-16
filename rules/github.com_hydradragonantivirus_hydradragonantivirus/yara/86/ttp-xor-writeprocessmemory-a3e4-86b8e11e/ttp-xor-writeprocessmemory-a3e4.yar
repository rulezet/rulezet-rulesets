rule TTP_XOR_WriteProcessMemory_a3e4 {
  strings:
    $key_a3e4 = { f4 96 [2] c6 b4 [2] c0 81 [2] ee 81 [2] d1 9d }

  condition:
    any of them
}