rule TTP_XOR_WriteProcessMemory_a351 {
  strings:
    $key_a351 = { f4 23 [2] c6 01 [2] c0 34 [2] ee 34 [2] d1 28 }

  condition:
    any of them
}