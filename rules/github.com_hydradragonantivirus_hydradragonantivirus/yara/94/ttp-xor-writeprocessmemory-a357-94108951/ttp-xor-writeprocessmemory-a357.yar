rule TTP_XOR_WriteProcessMemory_a357 {
  strings:
    $key_a357 = { f4 25 [2] c6 07 [2] c0 32 [2] ee 32 [2] d1 2e }

  condition:
    any of them
}