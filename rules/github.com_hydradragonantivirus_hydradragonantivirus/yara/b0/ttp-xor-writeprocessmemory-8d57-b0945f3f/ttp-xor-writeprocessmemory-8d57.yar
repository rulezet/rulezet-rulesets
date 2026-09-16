rule TTP_XOR_WriteProcessMemory_8d57 {
  strings:
    $key_8d57 = { da 25 [2] e8 07 [2] ee 32 [2] c0 32 [2] ff 2e }

  condition:
    any of them
}