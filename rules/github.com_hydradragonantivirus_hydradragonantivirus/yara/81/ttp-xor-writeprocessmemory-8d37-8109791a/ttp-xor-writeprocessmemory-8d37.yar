rule TTP_XOR_WriteProcessMemory_8d37 {
  strings:
    $key_8d37 = { da 45 [2] e8 67 [2] ee 52 [2] c0 52 [2] ff 4e }

  condition:
    any of them
}