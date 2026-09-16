rule TTP_XOR_WriteProcessMemory_8d7b {
  strings:
    $key_8d7b = { da 09 [2] e8 2b [2] ee 1e [2] c0 1e [2] ff 02 }

  condition:
    any of them
}