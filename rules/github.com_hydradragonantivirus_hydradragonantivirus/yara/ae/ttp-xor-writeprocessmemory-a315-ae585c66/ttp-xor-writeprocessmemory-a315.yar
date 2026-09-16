rule TTP_XOR_WriteProcessMemory_a315 {
  strings:
    $key_a315 = { f4 67 [2] c6 45 [2] c0 70 [2] ee 70 [2] d1 6c }

  condition:
    any of them
}