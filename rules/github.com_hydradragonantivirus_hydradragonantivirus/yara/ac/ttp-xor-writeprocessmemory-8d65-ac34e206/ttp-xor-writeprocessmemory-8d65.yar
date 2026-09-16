rule TTP_XOR_WriteProcessMemory_8d65 {
  strings:
    $key_8d65 = { da 17 [2] e8 35 [2] ee 00 [2] c0 00 [2] ff 1c }

  condition:
    any of them
}