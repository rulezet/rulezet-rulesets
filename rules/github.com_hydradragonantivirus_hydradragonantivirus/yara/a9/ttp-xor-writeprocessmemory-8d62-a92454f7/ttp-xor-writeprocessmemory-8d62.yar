rule TTP_XOR_WriteProcessMemory_8d62 {
  strings:
    $key_8d62 = { da 10 [2] e8 32 [2] ee 07 [2] c0 07 [2] ff 1b }

  condition:
    any of them
}