rule TTP_XOR_WriteProcessMemory_a3e3 {
  strings:
    $key_a3e3 = { f4 91 [2] c6 b3 [2] c0 86 [2] ee 86 [2] d1 9a }

  condition:
    any of them
}