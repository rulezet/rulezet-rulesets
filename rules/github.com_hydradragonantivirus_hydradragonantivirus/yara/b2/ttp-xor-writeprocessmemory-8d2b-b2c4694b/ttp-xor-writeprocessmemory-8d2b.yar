rule TTP_XOR_WriteProcessMemory_8d2b {
  strings:
    $key_8d2b = { da 59 [2] e8 7b [2] ee 4e [2] c0 4e [2] ff 52 }

  condition:
    any of them
}