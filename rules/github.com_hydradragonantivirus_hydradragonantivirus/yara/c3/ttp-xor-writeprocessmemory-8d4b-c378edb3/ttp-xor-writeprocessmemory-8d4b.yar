rule TTP_XOR_WriteProcessMemory_8d4b {
  strings:
    $key_8d4b = { da 39 [2] e8 1b [2] ee 2e [2] c0 2e [2] ff 32 }

  condition:
    any of them
}