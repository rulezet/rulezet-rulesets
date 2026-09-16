rule TTP_XOR_WriteProcessMemory_8d32 {
  strings:
    $key_8d32 = { da 40 [2] e8 62 [2] ee 57 [2] c0 57 [2] ff 4b }

  condition:
    any of them
}