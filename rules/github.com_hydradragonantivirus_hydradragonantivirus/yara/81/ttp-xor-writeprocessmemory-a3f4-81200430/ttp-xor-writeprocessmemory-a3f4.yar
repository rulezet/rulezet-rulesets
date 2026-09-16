rule TTP_XOR_WriteProcessMemory_a3f4 {
  strings:
    $key_a3f4 = { f4 86 [2] c6 a4 [2] c0 91 [2] ee 91 [2] d1 8d }

  condition:
    any of them
}