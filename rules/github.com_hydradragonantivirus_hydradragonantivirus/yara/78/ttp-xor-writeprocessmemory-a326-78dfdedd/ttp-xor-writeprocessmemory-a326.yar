rule TTP_XOR_WriteProcessMemory_a326 {
  strings:
    $key_a326 = { f4 54 [2] c6 76 [2] c0 43 [2] ee 43 [2] d1 5f }

  condition:
    any of them
}