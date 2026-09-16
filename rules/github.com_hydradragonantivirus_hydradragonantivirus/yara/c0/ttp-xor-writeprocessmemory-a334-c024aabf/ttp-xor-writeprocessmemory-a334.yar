rule TTP_XOR_WriteProcessMemory_a334 {
  strings:
    $key_a334 = { f4 46 [2] c6 64 [2] c0 51 [2] ee 51 [2] d1 4d }

  condition:
    any of them
}