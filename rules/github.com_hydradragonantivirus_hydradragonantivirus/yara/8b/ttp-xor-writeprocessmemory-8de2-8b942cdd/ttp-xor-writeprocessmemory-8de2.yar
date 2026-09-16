rule TTP_XOR_WriteProcessMemory_8de2 {
  strings:
    $key_8de2 = { da 90 [2] e8 b2 [2] ee 87 [2] c0 87 [2] ff 9b }

  condition:
    any of them
}