rule TTP_XOR_WriteProcessMemory_8d17 {
  strings:
    $key_8d17 = { da 65 [2] e8 47 [2] ee 72 [2] c0 72 [2] ff 6e }

  condition:
    any of them
}