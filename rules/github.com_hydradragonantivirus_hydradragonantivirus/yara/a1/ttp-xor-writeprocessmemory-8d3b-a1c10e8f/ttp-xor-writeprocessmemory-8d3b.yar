rule TTP_XOR_WriteProcessMemory_8d3b {
  strings:
    $key_8d3b = { da 49 [2] e8 6b [2] ee 5e [2] c0 5e [2] ff 42 }

  condition:
    any of them
}