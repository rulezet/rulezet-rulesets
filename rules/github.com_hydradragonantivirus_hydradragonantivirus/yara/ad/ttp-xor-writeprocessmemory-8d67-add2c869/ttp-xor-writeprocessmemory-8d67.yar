rule TTP_XOR_WriteProcessMemory_8d67 {
  strings:
    $key_8d67 = { da 15 [2] e8 37 [2] ee 02 [2] c0 02 [2] ff 1e }

  condition:
    any of them
}