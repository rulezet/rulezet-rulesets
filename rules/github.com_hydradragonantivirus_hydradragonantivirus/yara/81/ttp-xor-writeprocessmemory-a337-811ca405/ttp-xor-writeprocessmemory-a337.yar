rule TTP_XOR_WriteProcessMemory_a337 {
  strings:
    $key_a337 = { f4 45 [2] c6 67 [2] c0 52 [2] ee 52 [2] d1 4e }

  condition:
    any of them
}